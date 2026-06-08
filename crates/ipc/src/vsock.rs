// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Virtio socket (vsock) — host/guest IPC over `AF_VSOCK`.
//!
//! Implements the kernel-side model of the Linux `vhost_vsock` / `virtio-vsock`
//! subsystem (`net/vmw_vsock/`).  vsock provides a `AF_VSOCK` socket family that
//! allows bidirectional stream (`SOCK_STREAM`) and datagram (`SOCK_DGRAM`)
//! communication between a hypervisor host and its virtual machine guests
//! without requiring a network stack.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────┐
//! │ Guest (ONCRIX VM)                │
//! │  userspace ←→ AF_VSOCK ←→ vsock │
//! │                   │              │
//! │   virtio-vsock transport layer   │
//! └───────────────────┼──────────────┘
//!                     │ (virtqueue)
//! ┌───────────────────┼──────────────┐
//! │ Host (hypervisor) │              │
//! │   vhost-vsock ←───┘              │
//! │   host userspace process         │
//! └──────────────────────────────────┘
//! ```
//!
//! # Addressing
//!
//! A vsock address is a `(cid, port)` pair where:
//! - `cid` (Context ID) identifies the VM or the host.
//! - Well-known CIDs: `VMADDR_CID_ANY` (wildcard), `VMADDR_CID_LOCAL` (loopback),
//!   `VMADDR_CID_HOST` (hypervisor host).
//!
//! # What this module provides
//!
//! - [`VsockAddr`]      — socket address `(cid, port)`.
//! - [`VsockSocket`]    — a single vsock endpoint.
//! - [`VsockMessage`]   — a fixed-size message payload.
//! - [`VsockRegistry`]  — global socket table and routing.
//!
//! # Reference
//!
//! - Linux: `net/vmw_vsock/`, `include/uapi/linux/vm_sockets.h`
//! - VIRTIO spec: `virtio-vsock` (section 5.10)
//! - `man 7 vsock`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Well-known CID constants (mirrors `<linux/vm_sockets.h>`)
// ---------------------------------------------------------------------------

/// Wildcard CID — bind to any local CID.
pub const VMADDR_CID_ANY: u32 = u32::MAX;
/// Loopback CID — communicate within the same VM.
pub const VMADDR_CID_LOCAL: u32 = 1;
/// Host CID — the hypervisor / host OS endpoint.
pub const VMADDR_CID_HOST: u32 = 2;
/// Wildcard port — bind to any available port.
pub const VMADDR_PORT_ANY: u32 = u32::MAX;

/// AF_VSOCK address family identifier (mirrors Linux `AF_VSOCK = 40`).
pub const AF_VSOCK: u16 = 40;

/// Privileged user id (root).  Only this principal may bind a port below
/// [`VSOCK_MIN_DYNAMIC_PORT`].
pub const VSOCK_PRIV_UID: u32 = 0;

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Maximum number of vsock sockets in the global registry.
pub const VSOCK_MAX_SOCKETS: usize = 64;
/// Depth of each socket's receive queue (number of pending messages).
pub const VSOCK_RECV_QUEUE_DEPTH: usize = 32;
/// Maximum payload size per vsock message in bytes.
pub const VSOCK_MAX_MSG_SIZE: usize = 4096;
/// Minimum dynamic port number for auto-assignment.
pub const VSOCK_MIN_DYNAMIC_PORT: u32 = 1024;

// ---------------------------------------------------------------------------
// VsockAddr
// ---------------------------------------------------------------------------

/// A vsock socket address: `(cid, port)`.
///
/// Mirrors `struct sockaddr_vm` from `<linux/vm_sockets.h>`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct VsockAddr {
    /// Context ID of the peer or `VMADDR_CID_ANY` for wildcard bind.
    pub cid: u32,
    /// Port number or `VMADDR_PORT_ANY` for auto-assignment.
    pub port: u32,
}

impl VsockAddr {
    /// Create a new [`VsockAddr`].
    pub const fn new(cid: u32, port: u32) -> Self {
        Self { cid, port }
    }

    /// Returns `true` if `cid` is the wildcard `VMADDR_CID_ANY`.
    pub fn is_cid_any(&self) -> bool {
        self.cid == VMADDR_CID_ANY
    }

    /// Returns `true` if `port` is the wildcard `VMADDR_PORT_ANY`.
    pub fn is_port_any(&self) -> bool {
        self.port == VMADDR_PORT_ANY
    }
}

// ---------------------------------------------------------------------------
// VsockSocketType
// ---------------------------------------------------------------------------

/// Socket type for a vsock endpoint.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VsockSocketType {
    /// Reliable, ordered byte stream (analogous to TCP).
    #[default]
    Stream = 1,
    /// Unreliable datagrams (analogous to UDP).
    Dgram = 2,
    /// Sequenced packets.
    SeqPacket = 3,
}

impl VsockSocketType {
    /// Convert a raw socket type value to [`VsockSocketType`].
    pub fn from_raw(raw: u8) -> Result<Self> {
        match raw {
            1 => Ok(Self::Stream),
            2 => Ok(Self::Dgram),
            3 => Ok(Self::SeqPacket),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ---------------------------------------------------------------------------
// VsockState
// ---------------------------------------------------------------------------

/// Connection state of a vsock stream socket.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum VsockState {
    /// Socket created but not bound or connected.
    #[default]
    Closed,
    /// Bound to a local address; may accept connections.
    Bound,
    /// Listening for incoming connections (`SOCK_STREAM` only).
    Listening,
    /// Connection in progress (sent CONNECT, awaiting RESPONSE).
    Connecting,
    /// Fully established bidirectional stream.
    Connected,
    /// Local side has shut down writes; waiting for peer FIN.
    CloseWait,
}

// ---------------------------------------------------------------------------
// VsockMessage — fixed-size payload
// ---------------------------------------------------------------------------

/// A vsock message containing a fixed-size payload.
#[derive(Debug, Clone, Copy)]
pub struct VsockMessage {
    /// Source address of the message.
    pub src: VsockAddr,
    /// Destination address of the message.
    pub dst: VsockAddr,
    /// Payload bytes.
    pub payload: [u8; VSOCK_MAX_MSG_SIZE],
    /// Number of valid bytes in `payload`.
    pub len: usize,
}

impl VsockMessage {
    /// Create a new message with the given source, destination, and data.
    ///
    /// Returns `Err(InvalidArgument)` if `data` exceeds [`VSOCK_MAX_MSG_SIZE`].
    pub fn new(src: VsockAddr, dst: VsockAddr, data: &[u8]) -> Result<Self> {
        if data.len() > VSOCK_MAX_MSG_SIZE {
            return Err(Error::InvalidArgument);
        }
        let mut payload = [0u8; VSOCK_MAX_MSG_SIZE];
        payload[..data.len()].copy_from_slice(data);
        Ok(Self {
            src,
            dst,
            payload,
            len: data.len(),
        })
    }

    /// Returns a slice over the valid payload bytes.
    pub fn data(&self) -> &[u8] {
        // SECURITY: `len` and `payload` are public fields, so a hand-built
        // message can set `len` past the payload capacity; clamp to the
        // backing array length before slicing to avoid an OOB / ring-0 panic
        // (same guard as `VsockRegistry::recv`).
        &self.payload[..self.len.min(self.payload.len())]
    }
}

// ---------------------------------------------------------------------------
// VsockSocket
// ---------------------------------------------------------------------------

/// A single vsock socket endpoint.
#[derive(Debug)]
pub struct VsockSocket {
    /// Unique socket identifier (index into the registry).
    pub id: usize,
    /// Owning principal (user id) recorded at creation.
    ///
    /// Every lifecycle and data operation must present this same `owner`
    /// value; the registry rejects operations on a socket the caller does
    /// not own.  This binds the caller-supplied `socket_id` to an identity
    /// instead of trusting it blindly.
    owner: u32,
    /// Socket type.
    pub sock_type: VsockSocketType,
    /// Current connection state.
    pub state: VsockState,
    /// Local bound address.
    pub local: VsockAddr,
    /// Remote peer address (valid only in `Connected` state).
    pub peer: Option<VsockAddr>,
    /// Receive queue for incoming messages.
    recv_queue: [Option<VsockMessage>; VSOCK_RECV_QUEUE_DEPTH],
    /// Write index into `recv_queue`.
    recv_head: usize,
    /// Read index into `recv_queue`.
    recv_tail: usize,
    /// Number of messages currently in the receive queue.
    recv_count: usize,
}

impl VsockSocket {
    /// Create a new socket with the given ID, owner, and type.
    pub fn new(id: usize, owner: u32, sock_type: VsockSocketType) -> Self {
        Self {
            id,
            owner,
            sock_type,
            state: VsockState::Closed,
            local: VsockAddr::new(VMADDR_CID_ANY, VMADDR_PORT_ANY),
            peer: None,
            recv_queue: [const { None }; VSOCK_RECV_QUEUE_DEPTH],
            recv_head: 0,
            recv_tail: 0,
            recv_count: 0,
        }
    }

    /// Returns the owning principal (user id) of this socket.
    pub fn owner(&self) -> u32 {
        self.owner
    }

    /// Returns `true` if the receive queue has pending messages.
    pub fn has_data(&self) -> bool {
        self.recv_count > 0
    }

    /// Returns `true` if the socket is in a state that accepts inbound
    /// local datagrams (bound, listening, or fully connected).
    fn is_deliverable(&self) -> bool {
        matches!(
            self.state,
            VsockState::Bound | VsockState::Listening | VsockState::Connected
        )
    }

    /// Enqueue a message into the socket's receive buffer.
    ///
    /// Returns `Err(OutOfMemory)` if the receive queue is full.
    pub fn enqueue(&mut self, msg: VsockMessage) -> Result<()> {
        if self.recv_count >= VSOCK_RECV_QUEUE_DEPTH {
            return Err(Error::OutOfMemory);
        }
        self.recv_queue[self.recv_head] = Some(msg);
        self.recv_head = (self.recv_head + 1) % VSOCK_RECV_QUEUE_DEPTH;
        self.recv_count += 1;
        Ok(())
    }

    /// Dequeue the next message from the receive buffer.
    ///
    /// Returns `None` if the queue is empty.
    pub fn dequeue(&mut self) -> Option<VsockMessage> {
        if self.recv_count == 0 {
            return None;
        }
        let msg = self.recv_queue[self.recv_tail].take();
        self.recv_tail = (self.recv_tail + 1) % VSOCK_RECV_QUEUE_DEPTH;
        self.recv_count -= 1;
        msg
    }
}

// ---------------------------------------------------------------------------
// VsockRegistry — global socket table
// ---------------------------------------------------------------------------

/// Global vsock socket registry.
///
/// Maintains the table of all open vsock sockets and provides routing
/// for `send` operations (local delivery or virtio-vsock transport).
pub struct VsockRegistry {
    /// All registered sockets, indexed by socket ID.
    sockets: [Option<VsockSocket>; VSOCK_MAX_SOCKETS],
    /// Number of allocated sockets.
    count: usize,
    /// The CID of this VM (or host).  Packets whose `dst.cid` matches
    /// this value are delivered locally.
    local_cid: u32,
    /// Next port to use for auto-assignment.
    next_port: u32,
}

impl VsockRegistry {
    /// Create an empty registry for the VM with the given CID.
    pub const fn new(local_cid: u32) -> Self {
        Self {
            sockets: [const { None }; VSOCK_MAX_SOCKETS],
            count: 0,
            local_cid,
            next_port: VSOCK_MIN_DYNAMIC_PORT,
        }
    }

    // -----------------------------------------------------------------------
    // Bounds-checked + ownership-checked slot accessors
    // -----------------------------------------------------------------------

    /// Resolve a caller-supplied `socket_id` to an owned socket slot.
    ///
    /// Rejects out-of-range ids (no direct indexing — prevents an OOB
    /// panic in ring 0) and rejects access to a socket whose recorded
    /// `owner` does not match `owner`.  This stops a caller from operating
    /// on a `socket_id` it does not own (foreign-handle hijack).
    fn owned_slot_mut(&mut self, socket_id: usize, owner: u32) -> Result<&mut VsockSocket> {
        let socket = self
            .sockets
            .get_mut(socket_id)
            .ok_or(Error::InvalidArgument)?
            .as_mut()
            .ok_or(Error::InvalidArgument)?;
        if socket.owner != owner {
            return Err(Error::PermissionDenied);
        }
        Ok(socket)
    }

    /// Shared-reference counterpart to [`Self::owned_slot_mut`].
    fn owned_slot(&self, socket_id: usize, owner: u32) -> Result<&VsockSocket> {
        let socket = self
            .sockets
            .get(socket_id)
            .ok_or(Error::InvalidArgument)?
            .as_ref()
            .ok_or(Error::InvalidArgument)?;
        if socket.owner != owner {
            return Err(Error::PermissionDenied);
        }
        Ok(socket)
    }

    // -----------------------------------------------------------------------
    // Port allocation
    // -----------------------------------------------------------------------

    /// Allocate the next available dynamic port.
    fn alloc_port(&mut self) -> Result<u32> {
        let start = self.next_port;
        loop {
            let candidate = self.next_port;
            self.next_port = self.next_port.wrapping_add(1).max(VSOCK_MIN_DYNAMIC_PORT);
            if self.next_port < VSOCK_MIN_DYNAMIC_PORT {
                self.next_port = VSOCK_MIN_DYNAMIC_PORT;
            }
            // Check if any socket is already bound to this port.
            let in_use = self
                .sockets
                .iter()
                .any(|slot| slot.as_ref().map_or(false, |s| s.local.port == candidate));
            if !in_use {
                return Ok(candidate);
            }
            if self.next_port == start {
                return Err(Error::OutOfMemory);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Socket lifecycle
    // -----------------------------------------------------------------------

    /// Create a new vsock socket owned by `owner` and return its ID.
    ///
    /// The returned id is only usable by a caller presenting the same
    /// `owner` on subsequent operations.
    ///
    /// Returns `Err(OutOfMemory)` when the registry is full.
    pub fn socket(&mut self, owner: u32, sock_type: VsockSocketType) -> Result<usize> {
        if self.count >= VSOCK_MAX_SOCKETS {
            return Err(Error::OutOfMemory);
        }
        // Find the first free slot.
        let id = self
            .sockets
            .iter()
            .position(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;
        self.sockets[id] = Some(VsockSocket::new(id, owner, sock_type));
        self.count += 1;
        Ok(id)
    }

    /// Bind a socket to a local address.
    ///
    /// If `addr.port` is [`VMADDR_PORT_ANY`], a dynamic port is assigned.
    /// `addr.cid` must be either the local CID or `VMADDR_CID_ANY`.
    ///
    /// `owner` is the authenticated principal of the caller; it must match
    /// the socket's recorded owner.  Binding an explicit port below
    /// [`VSOCK_MIN_DYNAMIC_PORT`] requires `owner == VSOCK_PRIV_UID`
    /// (fail-closed), mirroring `CAP_NET_BIND_SERVICE`.  The syscall layer
    /// must pass the authenticated caller uid here.
    pub fn bind(&mut self, socket_id: usize, owner: u32, mut addr: VsockAddr) -> Result<()> {
        let cid = self.local_cid;

        // Reject foreign socket_id and out-of-range ids before any indexing.
        let socket = self.owned_slot_mut(socket_id, owner)?;

        if socket.state != VsockState::Closed {
            return Err(Error::InvalidArgument);
        }
        if !addr.is_cid_any() && addr.cid != cid {
            return Err(Error::InvalidArgument);
        }
        // Privileged-port gate: an explicit well-known port requires root.
        // The wildcard port is allocated dynamically (>= MIN_DYNAMIC_PORT)
        // below and is therefore unprivileged.
        if !addr.is_port_any() && addr.port < VSOCK_MIN_DYNAMIC_PORT && owner != VSOCK_PRIV_UID {
            return Err(Error::PermissionDenied);
        }
        if addr.is_cid_any() {
            addr.cid = cid;
        }
        // Port assignment is handled below (needs mutable self).
        let _ = socket;

        if addr.is_port_any() {
            addr.port = self.alloc_port()?;
        }

        let socket = self.owned_slot_mut(socket_id, owner)?;
        socket.local = addr;
        socket.state = VsockState::Bound;
        Ok(())
    }

    /// Put a stream socket into the listening state.
    ///
    /// `owner` must match the socket's recorded owner.  `_backlog` is
    /// accepted but ignored in this stub implementation.
    pub fn listen(&mut self, socket_id: usize, owner: u32, _backlog: i32) -> Result<()> {
        let socket = self.owned_slot_mut(socket_id, owner)?;
        if socket.sock_type != VsockSocketType::Stream {
            return Err(Error::NotImplemented);
        }
        if socket.state != VsockState::Bound {
            return Err(Error::InvalidArgument);
        }
        socket.state = VsockState::Listening;
        Ok(())
    }

    /// Initiate a connection to a remote address.
    ///
    /// `owner` must match the socket's recorded owner.  The socket
    /// transitions to `Connecting`; full handshake completion requires the
    /// virtio-vsock transport layer (stub).
    pub fn connect(&mut self, socket_id: usize, owner: u32, peer: VsockAddr) -> Result<()> {
        let local_cid = self.local_cid;
        let socket = self.owned_slot_mut(socket_id, owner)?;
        if socket.sock_type != VsockSocketType::Stream {
            return Err(Error::NotImplemented);
        }
        if peer.cid == VMADDR_CID_ANY {
            return Err(Error::InvalidArgument);
        }
        if peer.port == VMADDR_PORT_ANY {
            return Err(Error::InvalidArgument);
        }

        // Auto-assign local port if needed.
        if socket.local.port == VMADDR_PORT_ANY {
            let _ = socket;
            let port = self.alloc_port()?;
            let socket = self.owned_slot_mut(socket_id, owner)?;
            socket.local = VsockAddr::new(local_cid, port);
        }

        let socket = self.owned_slot_mut(socket_id, owner)?;
        socket.peer = Some(peer);
        socket.state = VsockState::Connecting;

        // Stub: real implementation sends a VIRTIO_VSOCK_OP_REQUEST
        // packet over the virtqueue and waits for RESPONSE.
        Err(Error::NotImplemented)
    }

    /// Close and release a socket.
    ///
    /// `owner` must match the socket's recorded owner; a caller cannot
    /// close a socket it does not own.
    pub fn close(&mut self, socket_id: usize, owner: u32) -> Result<()> {
        // Validates bounds + ownership; on Ok, `socket_id` is in range.
        let socket = self.owned_slot_mut(socket_id, owner)?;
        socket.state = VsockState::Closed;
        self.sockets[socket_id] = None;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Data transfer
    // -----------------------------------------------------------------------

    /// Send a message from `socket_id` to the address in `dst`.
    ///
    /// `owner` must match the sending socket's recorded owner; a caller
    /// cannot send from a `socket_id` it does not own (this also stamps a
    /// trustworthy source address rather than one the caller spoofed).
    ///
    /// For local CID destinations the message is delivered directly to the
    /// matching bound socket's receive queue.  A target qualifies only when
    /// its CID **and** port match `dst` and it is in a deliverable state —
    /// preventing cross-CID hijack and delivery into wildcard/unbound
    /// sockets.  For remote CIDs the message is forwarded to the
    /// virtio-vsock transport (stub).
    pub fn send(
        &mut self,
        socket_id: usize,
        owner: u32,
        data: &[u8],
        dst: VsockAddr,
    ) -> Result<usize> {
        // Reject foreign/out-of-range socket_id; derive an authentic source.
        let src = self.owned_slot(socket_id, owner)?.local;
        let msg = VsockMessage::new(src, dst, data)?;

        // Local delivery only when the destination CID is *this* registry's
        // CID.  `VMADDR_CID_LOCAL` (loopback) is local only when we are that
        // CID; it must not alias an arbitrary host/guest registry.
        let is_local = dst.cid == self.local_cid
            || (dst.cid == VMADDR_CID_LOCAL && self.local_cid == VMADDR_CID_LOCAL);
        if is_local {
            // A wildcard destination CID/port can never name a concrete
            // listener; reject rather than fan out to every socket.
            if dst.is_cid_any() || dst.is_port_any() {
                return Err(Error::NotFound);
            }
            // Match on the full (cid, port) tuple, an accepting state, and
            // exclude the sender itself.
            let target = self.sockets.iter_mut().find(|s| {
                s.as_ref().is_some_and(|s| {
                    s.id != socket_id
                        && s.local.port == dst.port
                        && s.local.cid == dst.cid
                        && s.is_deliverable()
                })
            });
            if let Some(Some(target_sock)) = target {
                target_sock.enqueue(msg)?;
                return Ok(data.len());
            }
            return Err(Error::NotFound);
        }

        // Remote delivery: hand off to virtio-vsock transport (stub).
        let _ = msg;
        Err(Error::NotImplemented)
    }

    /// Receive a message into `buf` from the socket's queue.
    ///
    /// `owner` must match the socket's recorded owner; a caller cannot
    /// drain a queue it does not own.
    ///
    /// Returns the number of bytes copied into `buf`, or
    /// `Err(WouldBlock)` if the queue is empty.
    pub fn recv(&mut self, socket_id: usize, owner: u32, buf: &mut [u8]) -> Result<usize> {
        let socket = self.owned_slot_mut(socket_id, owner)?;
        let msg = socket.dequeue().ok_or(Error::WouldBlock)?;
        // SECURITY: `msg.len` is a public field and may exceed the actual
        // `payload` capacity (a caller can build a `VsockMessage` with a
        // bogus `len` via the public fields), so bound the copy by the real
        // payload length as well — otherwise `&msg.payload[..n]` is an OOB
        // slice / ring-0 panic.
        let n = msg.len.min(buf.len()).min(msg.payload.len());
        buf[..n].copy_from_slice(&msg.payload[..n]);
        Ok(n)
    }

    // -----------------------------------------------------------------------
    // Query helpers
    // -----------------------------------------------------------------------

    /// Look up a socket by ID.
    pub fn get(&self, socket_id: usize) -> Option<&VsockSocket> {
        self.sockets.get(socket_id)?.as_ref()
    }

    /// Look up a socket by ID (mutable), crate-internal only.
    ///
    /// NOT public: a mutable handle that skipped the `owner` check would let
    /// a caller bypass ownership. External mutation must go through the
    /// owner-checked lifecycle/data ops (`bind`/`connect`/`send`/...).
    fn get_mut(&mut self, socket_id: usize) -> Option<&mut VsockSocket> {
        self.sockets.get_mut(socket_id)?.as_mut()
    }

    /// Return the local CID of this registry.
    pub fn local_cid(&self) -> u32 {
        self.local_cid
    }

    /// Number of open sockets.
    pub fn socket_count(&self) -> usize {
        self.count
    }
}
