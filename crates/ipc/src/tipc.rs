// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! TIPC — Transparent Inter-Process Communication.
//!
//! Implements a kernel-space model of the Linux TIPC protocol
//! (`net/tipc/`).  TIPC is a cluster-oriented IPC protocol designed for
//! high-availability systems.  Unlike socket-oriented IPC, TIPC uses
//! *service addresses* (type, instance) that are independent of the
//! underlying network topology.  Messages are routed by the TIPC name
//! table, not by IP addresses or port numbers.
//!
//! # What this module provides
//!
//! * **[`TipcAddr`]** — a TIPC address (node, port, or service).
//! * **[`TipcServiceAddr`]** — (type, instance) service name.
//! * **[`TipcServiceRange`]** — a (type, lower..=upper) service range.
//! * **[`TipcSocket`]** — a TIPC endpoint (SOCK_RDM / SOCK_SEQPACKET /
//!   SOCK_STREAM / SOCK_DGRAM).
//! * **[`TipcMessage`]** — a fixed-size message payload.
//! * **[`TipcNameTable`]** — global service-name → socket binding table.
//! * **[`TipcRegistry`]** — global socket table.
//! * High-level operations: `bind`, `connect`, `send`, `recv`,
//!   `subscribe`, `unsubscribe`.
//!
//! # Protocol overview
//!
//! ```text
//! Server                              Client
//! ──────                              ──────
//! socket(TIPC, SEQPACKET) → fd_s     socket(TIPC, SEQPACKET) → fd_c
//! bind(fd_s, {type=1234, inst=1})    connect(fd_c, {type=1234, inst=1})
//! accept(fd_s) → fd_conn             ──MSG──►  recv(fd_conn, …)
//!                                    ◄──MSG──  send(fd_conn, …)
//! ```
//!
//! # Reference
//!
//! - Linux: `net/tipc/`, `include/uapi/linux/tipc.h`
//! - RFC: TIPC 2.0 specification (Ericsson)

#[allow(dead_code)]
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Maximum number of TIPC sockets the registry can hold.
pub const TIPC_MAX_SOCKETS: usize = 64;

/// Maximum number of name-table bindings (service → socket).
pub const TIPC_MAX_BINDINGS: usize = 128;

/// Maximum number of topology subscriptions.
pub const TIPC_MAX_SUBSCRIPTIONS: usize = 32;

/// Maximum message payload size in bytes.
pub const TIPC_MAX_MSG_SIZE: usize = 256;

/// Maximum number of messages in a socket's receive queue.
pub const TIPC_RECV_QUEUE_DEPTH: usize = 16;

// ---------------------------------------------------------------------------
// Address constants
// ---------------------------------------------------------------------------

/// TIPC address family identifier (mirrors `AF_TIPC = 30` in Linux).
pub const AF_TIPC: u16 = 30;

/// Node scope: message stays within this cluster node.
pub const TIPC_NODE_SCOPE: u32 = 1;
/// Cluster scope: message may be delivered anywhere in the cluster.
pub const TIPC_CLUSTER_SCOPE: u32 = 2;
/// Zone scope: message may be delivered to any zone in the network.
pub const TIPC_ZONE_SCOPE: u32 = 3;

// ---------------------------------------------------------------------------
// TipcServiceAddr
// ---------------------------------------------------------------------------

/// A TIPC service address — (type, instance) pair.
///
/// Service *type* identifies the kind of service (application-defined).
/// Service *instance* identifies a specific provider of that service.
/// Multiple sockets may bind to overlapping instance ranges of the same
/// type; TIPC performs load-spreading across them.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TipcServiceAddr {
    /// Service type (application-defined, non-zero).
    pub service_type: u32,
    /// Service instance.
    pub instance: u32,
}

impl TipcServiceAddr {
    /// Create a new service address.
    pub const fn new(service_type: u32, instance: u32) -> Self {
        Self {
            service_type,
            instance,
        }
    }

    /// Validate: service type must be non-zero.
    pub fn validate(&self) -> Result<()> {
        if self.service_type == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TipcServiceRange
// ---------------------------------------------------------------------------

/// A range of service instances for publishing or subscribing.
///
/// Represents all instances `[lower, upper]` of a given service type.
/// Used in `bind`, `unbind`, and topology subscriptions.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TipcServiceRange {
    /// Service type.
    pub service_type: u32,
    /// First instance in the range (inclusive).
    pub lower: u32,
    /// Last instance in the range (inclusive).
    pub upper: u32,
}

impl TipcServiceRange {
    /// Create a range covering a single instance.
    pub const fn single(service_type: u32, instance: u32) -> Self {
        Self {
            service_type,
            lower: instance,
            upper: instance,
        }
    }

    /// Create a range covering `[lower, upper]`.
    pub const fn new(service_type: u32, lower: u32, upper: u32) -> Self {
        Self {
            service_type,
            lower,
            upper,
        }
    }

    /// Validate: service type non-zero and `lower <= upper`.
    pub fn validate(&self) -> Result<()> {
        if self.service_type == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.lower > self.upper {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Returns `true` if `addr` falls within this range.
    pub const fn contains(&self, addr: &TipcServiceAddr) -> bool {
        self.service_type == addr.service_type
            && addr.instance >= self.lower
            && addr.instance <= self.upper
    }
}

// ---------------------------------------------------------------------------
// TipcAddr
// ---------------------------------------------------------------------------

/// A TIPC address, which may be a port address or service address.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TipcAddr {
    /// A port address — (node, ref) pair uniquely identifies a socket.
    Port {
        /// Logical node identifier.
        node: u32,
        /// Port reference (unique per node).
        port_ref: u32,
    },
    /// A service address — (type, instance).
    Service(TipcServiceAddr),
    /// A service range address used for binding.
    ServiceRange(TipcServiceRange),
}

// ---------------------------------------------------------------------------
// TipcSocketType
// ---------------------------------------------------------------------------

/// TIPC socket communication type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TipcSocketType {
    /// Reliable datagram (unordered, no connection).
    #[default]
    Rdm,
    /// Reliable sequenced packets (connection-oriented, message boundaries).
    Seqpacket,
    /// Reliable byte stream (connection-oriented, no message boundaries).
    Stream,
    /// Unreliable datagram.
    Dgram,
}

// ---------------------------------------------------------------------------
// TipcSocketState
// ---------------------------------------------------------------------------

/// State machine for a TIPC socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TipcSocketState {
    /// Socket created but not bound.
    #[default]
    Unbound,
    /// Socket bound to a service name (server side).
    Bound,
    /// Connect request issued, awaiting server acceptance.
    Connecting,
    /// Connection established (stream/seqpacket).
    Connected,
    /// Remote end has closed; local end may still drain receive queue.
    Disconnecting,
    /// Socket closed.
    Closed,
}

// ---------------------------------------------------------------------------
// TipcMessage
// ---------------------------------------------------------------------------

/// A fixed-size TIPC message with inline payload.
#[derive(Debug, Clone, Copy)]
pub struct TipcMessage {
    /// Source socket index (index into the registry).
    pub src_sock: usize,
    /// Payload size in bytes.
    pub len: usize,
    /// Inline payload buffer.
    pub data: [u8; TIPC_MAX_MSG_SIZE],
    /// Service address the message was sent to (for service-addressed msgs).
    pub dest_service: Option<TipcServiceAddr>,
}

impl TipcMessage {
    /// Create a new message from a byte slice.
    ///
    /// Truncates silently if `payload` is longer than [`TIPC_MAX_MSG_SIZE`].
    pub fn new(src: usize, payload: &[u8], dest: Option<TipcServiceAddr>) -> Self {
        let mut data = [0u8; TIPC_MAX_MSG_SIZE];
        let len = payload.len().min(TIPC_MAX_MSG_SIZE);
        data[..len].copy_from_slice(&payload[..len]);
        Self {
            src_sock: src,
            len,
            data,
            dest_service: dest,
        }
    }

    /// Return the payload as a slice.
    pub fn payload(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

// ---------------------------------------------------------------------------
// TipcSocket
// ---------------------------------------------------------------------------

/// A TIPC socket endpoint.
#[derive(Debug)]
pub struct TipcSocket {
    /// Index in the global socket table (also the "port ref" on node 0).
    pub index: usize,
    /// Socket type.
    pub sock_type: TipcSocketType,
    /// Current state.
    pub state: TipcSocketState,
    /// The service range this socket is currently bound to (if any).
    pub binding: Option<TipcServiceRange>,
    /// Index of the peer socket for connected sockets.
    pub peer: Option<usize>,
    /// Receive queue (ring buffer of messages).
    recv_queue: [Option<TipcMessage>; TIPC_RECV_QUEUE_DEPTH],
    /// Number of messages waiting in the receive queue.
    recv_count: usize,
    /// Write index for the receive queue.
    recv_head: usize,
    /// Read index for the receive queue.
    recv_tail: usize,
    /// Whether the socket is in non-blocking mode.
    pub nonblocking: bool,
}

impl TipcSocket {
    /// Create a new, unbound TIPC socket.
    const fn new(index: usize, sock_type: TipcSocketType) -> Self {
        Self {
            index,
            sock_type,
            state: TipcSocketState::Unbound,
            binding: None,
            peer: None,
            recv_queue: [None; TIPC_RECV_QUEUE_DEPTH],
            recv_count: 0,
            recv_head: 0,
            recv_tail: 0,
            nonblocking: false,
        }
    }

    /// Enqueue a received message.
    ///
    /// Returns `Err(Error::OutOfMemory)` when the receive queue is full.
    fn enqueue(&mut self, msg: TipcMessage) -> Result<()> {
        if self.recv_count >= TIPC_RECV_QUEUE_DEPTH {
            return Err(Error::OutOfMemory);
        }
        self.recv_queue[self.recv_head] = Some(msg);
        self.recv_head = (self.recv_head + 1) % TIPC_RECV_QUEUE_DEPTH;
        self.recv_count += 1;
        Ok(())
    }

    /// Dequeue the oldest message.
    ///
    /// Returns `None` when the queue is empty.
    fn dequeue(&mut self) -> Option<TipcMessage> {
        if self.recv_count == 0 {
            return None;
        }
        let msg = self.recv_queue[self.recv_tail].take();
        self.recv_tail = (self.recv_tail + 1) % TIPC_RECV_QUEUE_DEPTH;
        self.recv_count -= 1;
        msg
    }

    /// Return the number of messages waiting.
    pub const fn pending(&self) -> usize {
        self.recv_count
    }
}

// ---------------------------------------------------------------------------
// TipcBinding — name-table entry
// ---------------------------------------------------------------------------

/// A single name-table entry: service range → socket index.
#[derive(Debug, Clone, Copy)]
struct TipcBinding {
    /// The published service range.
    range: TipcServiceRange,
    /// Index of the socket that published it.
    sock: usize,
    /// Scope (NODE_SCOPE, CLUSTER_SCOPE, ZONE_SCOPE).
    scope: u32,
}

// ---------------------------------------------------------------------------
// TipcSubscription — topology subscription
// ---------------------------------------------------------------------------

/// Records interest in publications within a service range.
///
/// When a matching `bind` or `unbind` occurs, the subscriber's socket
/// receives a [`TipcTopologyEvent`].
#[derive(Debug, Clone, Copy)]
pub struct TipcSubscription {
    /// Range of interest.
    pub range: TipcServiceRange,
    /// Socket to deliver events to.
    pub subscriber_sock: usize,
    /// Sequence number (for matching unsub requests).
    pub seq: u32,
}

/// A topology event delivered to a subscriber.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TipcTopologyEvent {
    /// A service in the subscribed range became available.
    Published {
        /// The service that was published.
        addr: TipcServiceAddr,
        /// Socket that published it.
        sock: usize,
    },
    /// A service in the subscribed range was withdrawn.
    Withdrawn {
        /// The service that was withdrawn.
        addr: TipcServiceAddr,
        /// Socket that withdrew it.
        sock: usize,
    },
}

// ---------------------------------------------------------------------------
// TipcRegistry — global state
// ---------------------------------------------------------------------------

/// Global TIPC socket registry and name table.
///
/// In a real kernel this would be per-net-namespace and protected by
/// per-subsystem locks.  Here it is a flat, no_std static structure.
pub struct TipcRegistry {
    /// Socket table (slot 0 unused as sentinel).
    sockets: [Option<TipcSocket>; TIPC_MAX_SOCKETS],
    /// Name-table bindings.
    bindings: [Option<TipcBinding>; TIPC_MAX_BINDINGS],
    /// Topology subscriptions.
    subscriptions: [Option<TipcSubscription>; TIPC_MAX_SUBSCRIPTIONS],
    /// Monotonically increasing subscription sequence counter.
    sub_seq: u32,
    /// Monotonically increasing port-reference counter.
    port_ref_next: u32,
}

impl TipcRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            sockets: [const { None }; TIPC_MAX_SOCKETS],
            bindings: [const { None }; TIPC_MAX_BINDINGS],
            subscriptions: [const { None }; TIPC_MAX_SUBSCRIPTIONS],
            sub_seq: 1,
            port_ref_next: 1,
        }
    }

    // -----------------------------------------------------------------------
    // Socket lifecycle
    // -----------------------------------------------------------------------

    /// Create a new TIPC socket.
    ///
    /// Returns the socket index (fd equivalent) on success.
    ///
    /// # Errors
    ///
    /// `OutOfMemory` when all socket slots are taken.
    pub fn socket(&mut self, sock_type: TipcSocketType) -> Result<usize> {
        for (i, slot) in self.sockets.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(TipcSocket::new(i, sock_type));
                self.port_ref_next = self.port_ref_next.wrapping_add(1);
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Close a TIPC socket.
    ///
    /// Removes all name-table bindings published by this socket,
    /// notifies topology subscribers, and disconnects any connected peer.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` for an invalid or already-closed socket index.
    pub fn close(&mut self, sock: usize) -> Result<()> {
        if sock >= TIPC_MAX_SOCKETS || self.sockets[sock].is_none() {
            return Err(Error::InvalidArgument);
        }

        // Unbind all name-table entries for this socket.
        for slot in self.bindings.iter_mut() {
            if let Some(b) = slot {
                if b.sock == sock {
                    *slot = None;
                }
            }
        }

        // Disconnect peer if connected.
        if let Some(ref s) = self.sockets[sock] {
            if let Some(peer_idx) = s.peer {
                if let Some(ref mut peer) = self.sockets[peer_idx] {
                    peer.peer = None;
                    peer.state = TipcSocketState::Disconnecting;
                }
            }
        }

        self.sockets[sock] = None;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // bind / unbind
    // -----------------------------------------------------------------------

    /// Bind a socket to a service range.
    ///
    /// Publishes the (type, lower..=upper) service range so that other
    /// TIPC nodes can send messages to this socket by service address.
    /// Notifies any matching topology subscribers.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — invalid socket, invalid range, or invalid scope.
    /// * `OutOfMemory` — name-table is full.
    pub fn bind(&mut self, sock: usize, range: TipcServiceRange, scope: u32) -> Result<()> {
        range.validate()?;
        if scope < TIPC_NODE_SCOPE || scope > TIPC_ZONE_SCOPE {
            return Err(Error::InvalidArgument);
        }
        if sock >= TIPC_MAX_SOCKETS || self.sockets[sock].is_none() {
            return Err(Error::InvalidArgument);
        }

        // Find a free binding slot.
        let slot = self
            .bindings
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;

        *slot = Some(TipcBinding { range, sock, scope });

        // Update socket state.
        if let Some(ref mut s) = self.sockets[sock] {
            s.binding = Some(range);
            if s.state == TipcSocketState::Unbound {
                s.state = TipcSocketState::Bound;
            }
        }

        // Notify topology subscribers for each instance in the range.
        for inst in range.lower..=range.upper {
            let addr = TipcServiceAddr::new(range.service_type, inst);
            self.notify_subscribers(TipcTopologyEvent::Published { addr, sock });
        }

        Ok(())
    }

    /// Unbind a socket from its current service range.
    ///
    /// If `range` is `None`, removes all bindings for the socket.
    /// Notifies topology subscribers.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` — invalid socket index.
    pub fn unbind(&mut self, sock: usize, range: Option<TipcServiceRange>) -> Result<()> {
        if sock >= TIPC_MAX_SOCKETS || self.sockets[sock].is_none() {
            return Err(Error::InvalidArgument);
        }

        // Collect removed ranges first to avoid conflicting borrows.
        let mut removed: [Option<TipcServiceRange>; TIPC_MAX_BINDINGS] = [None; TIPC_MAX_BINDINGS];
        let mut removed_count = 0;

        for slot in self.bindings.iter_mut() {
            if let Some(b) = slot {
                if b.sock != sock {
                    continue;
                }
                if let Some(ref target) = range {
                    if b.range.service_type != target.service_type
                        || b.range.lower != target.lower
                        || b.range.upper != target.upper
                    {
                        continue;
                    }
                }
                removed[removed_count] = Some(b.range);
                removed_count += 1;
                *slot = None;
            }
        }

        let found = removed_count > 0;

        // Notify subscribers after bindings table is updated.
        for i in 0..removed_count {
            if let Some(removed_range) = removed[i] {
                for inst in removed_range.lower..=removed_range.upper {
                    let addr = TipcServiceAddr::new(removed_range.service_type, inst);
                    self.notify_subscribers(TipcTopologyEvent::Withdrawn { addr, sock });
                }
            }
        }

        if found {
            if let Some(ref mut s) = self.sockets[sock] {
                if range.is_none() {
                    s.binding = None;
                    if s.state == TipcSocketState::Bound {
                        s.state = TipcSocketState::Unbound;
                    }
                }
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // connect / accept
    // -----------------------------------------------------------------------

    /// Initiate a connection from `client_sock` to a service address.
    ///
    /// Looks up the service address in the name table and pairs the
    /// client socket with the first matching server socket.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — invalid socket or service address.
    /// * `NotFound` — no socket is bound to the service address.
    /// * `AlreadyExists` — socket is already connected.
    pub fn connect(&mut self, client_sock: usize, service: TipcServiceAddr) -> Result<()> {
        service.validate()?;

        if client_sock >= TIPC_MAX_SOCKETS {
            return Err(Error::InvalidArgument);
        }
        {
            let sock = self.sockets[client_sock]
                .as_ref()
                .ok_or(Error::InvalidArgument)?;
            if sock.state == TipcSocketState::Connected {
                return Err(Error::AlreadyExists);
            }
        }

        // Find a bound server socket that covers the service address.
        let server_idx = self
            .bindings
            .iter()
            .filter_map(|b| b.as_ref())
            .find(|b| b.range.contains(&service))
            .map(|b| b.sock)
            .ok_or(Error::NotFound)?;

        // Wire up the connection.
        if let Some(ref mut c) = self.sockets[client_sock] {
            c.peer = Some(server_idx);
            c.state = TipcSocketState::Connected;
        }
        if let Some(ref mut s) = self.sockets[server_idx] {
            s.peer = Some(client_sock);
            s.state = TipcSocketState::Connected;
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // send / recv
    // -----------------------------------------------------------------------

    /// Send a message from `src_sock`.
    ///
    /// For connected sockets the message goes directly to the peer's
    /// receive queue.  For unconnected sockets a `dest` service address
    /// must be provided; the name table is consulted to find a receiver.
    ///
    /// # Arguments
    ///
    /// * `src_sock` — sending socket index
    /// * `payload`  — message bytes (truncated to [`TIPC_MAX_MSG_SIZE`])
    /// * `dest`     — destination service address (for unconnected sends)
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — invalid socket.
    /// * `NotFound` — no bound socket for service address.
    /// * `OutOfMemory` — receiver's queue is full.
    pub fn send(
        &mut self,
        src_sock: usize,
        payload: &[u8],
        dest: Option<TipcServiceAddr>,
    ) -> Result<usize> {
        if src_sock >= TIPC_MAX_SOCKETS || self.sockets[src_sock].is_none() {
            return Err(Error::InvalidArgument);
        }

        let dest_idx = {
            let sock = self.sockets[src_sock].as_ref().unwrap();
            if let Some(peer) = sock.peer {
                peer
            } else {
                // Connectionless — look up by service address.
                let service = dest.ok_or(Error::InvalidArgument)?;
                service.validate()?;
                self.bindings
                    .iter()
                    .filter_map(|b| b.as_ref())
                    .find(|b| b.range.contains(&service))
                    .map(|b| b.sock)
                    .ok_or(Error::NotFound)?
            }
        };

        let msg = TipcMessage::new(src_sock, payload, dest);
        let len = msg.len;

        if dest_idx >= TIPC_MAX_SOCKETS {
            return Err(Error::InvalidArgument);
        }
        let dest_sock = self.sockets[dest_idx]
            .as_mut()
            .ok_or(Error::InvalidArgument)?;
        dest_sock.enqueue(msg)?;

        Ok(len)
    }

    /// Receive a message on `sock`.
    ///
    /// Copies the payload into `buf` and returns the number of bytes
    /// written.  If the socket is in non-blocking mode and no message is
    /// available, returns `Err(Error::WouldBlock)`.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — invalid socket index.
    /// * `WouldBlock` — queue empty and socket is non-blocking.
    pub fn recv(&mut self, sock: usize, buf: &mut [u8]) -> Result<usize> {
        if sock >= TIPC_MAX_SOCKETS {
            return Err(Error::InvalidArgument);
        }
        let socket = self.sockets[sock].as_mut().ok_or(Error::InvalidArgument)?;

        let msg = if socket.nonblocking {
            socket.dequeue().ok_or(Error::WouldBlock)?
        } else {
            // Blocking stub: if empty return WouldBlock (real impl would sleep).
            socket.dequeue().ok_or(Error::WouldBlock)?
        };

        let copy_len = buf.len().min(msg.len);
        buf[..copy_len].copy_from_slice(&msg.data[..copy_len]);
        Ok(copy_len)
    }

    // -----------------------------------------------------------------------
    // Topology subscriptions
    // -----------------------------------------------------------------------

    /// Subscribe to topology events for a service range.
    ///
    /// When a socket is bound or unbound within `range`, a
    /// [`TipcTopologyEvent`] is delivered to `subscriber_sock`'s
    /// receive queue as a raw event (serialized into a synthetic
    /// 16-byte payload for queue compatibility).
    ///
    /// Returns the subscription sequence number (used for unsubscribe).
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — invalid socket or range.
    /// * `OutOfMemory` — subscription table is full.
    pub fn subscribe(&mut self, subscriber_sock: usize, range: TipcServiceRange) -> Result<u32> {
        range.validate()?;
        if subscriber_sock >= TIPC_MAX_SOCKETS || self.sockets[subscriber_sock].is_none() {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .subscriptions
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;

        let seq = self.sub_seq;
        self.sub_seq = self.sub_seq.wrapping_add(1);

        *slot = Some(TipcSubscription {
            range,
            subscriber_sock,
            seq,
        });

        Ok(seq)
    }

    /// Cancel a topology subscription by its sequence number.
    ///
    /// # Errors
    ///
    /// `NotFound` — no subscription with `seq` exists.
    pub fn unsubscribe(&mut self, seq: u32) -> Result<()> {
        for slot in self.subscriptions.iter_mut() {
            if let Some(s) = slot {
                if s.seq == seq {
                    *slot = None;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    // -----------------------------------------------------------------------
    // Name-table lookup
    // -----------------------------------------------------------------------

    /// Look up all socket indices bound to a service address.
    ///
    /// Fills `out` with socket indices and returns the count found.
    /// `out` is not sorted; ordering is unspecified.
    pub fn lookup(&self, service: TipcServiceAddr, out: &mut [usize]) -> usize {
        let mut count = 0;
        for binding in self.bindings.iter().filter_map(|b| b.as_ref()) {
            if count >= out.len() {
                break;
            }
            if binding.range.contains(&service) {
                out[count] = binding.sock;
                count += 1;
            }
        }
        count
    }

    // -----------------------------------------------------------------------
    // Query helpers
    // -----------------------------------------------------------------------

    /// Return the number of open sockets.
    pub fn socket_count(&self) -> usize {
        self.sockets.iter().filter(|s| s.is_some()).count()
    }

    /// Return the number of active name-table bindings.
    pub fn binding_count(&self) -> usize {
        self.bindings.iter().filter(|b| b.is_some()).count()
    }

    /// Return the number of active topology subscriptions.
    pub fn subscription_count(&self) -> usize {
        self.subscriptions.iter().filter(|s| s.is_some()).count()
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Deliver a topology event to all matching subscribers.
    fn notify_subscribers(&mut self, event: TipcTopologyEvent) {
        // Collect subscriber sockets to notify (avoid mutable borrow conflict).
        let mut notify: [usize; TIPC_MAX_SUBSCRIPTIONS] = [usize::MAX; TIPC_MAX_SUBSCRIPTIONS];
        let mut count = 0;

        let (addr, is_pub) = match event {
            TipcTopologyEvent::Published { addr, .. } => (addr, true),
            TipcTopologyEvent::Withdrawn { addr, .. } => (addr, false),
        };

        for sub in self.subscriptions.iter().filter_map(|s| s.as_ref()) {
            if sub.range.contains(&addr) && count < TIPC_MAX_SUBSCRIPTIONS {
                notify[count] = sub.subscriber_sock;
                count += 1;
            }
        }

        // Encode the event as a 16-byte synthetic payload.
        // Layout: [type:4][instance:4][is_pub:1][pad:7]
        let mut payload = [0u8; 16];
        payload[0..4].copy_from_slice(&addr.service_type.to_le_bytes());
        payload[4..8].copy_from_slice(&addr.instance.to_le_bytes());
        payload[8] = u8::from(is_pub);

        for i in 0..count {
            let sock_idx = notify[i];
            if sock_idx >= TIPC_MAX_SOCKETS {
                continue;
            }
            if let Some(ref mut sock) = self.sockets[sock_idx] {
                let msg = TipcMessage::new(usize::MAX, &payload, None);
                // Ignore queue-full errors for topology events.
                let _ = sock.enqueue(msg);
            }
        }
    }
}

impl Default for TipcRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Global registry (single-node stub)
// ---------------------------------------------------------------------------

/// Global TIPC registry for ONCRIX (single-node scope).
static mut TIPC_REGISTRY: TipcRegistry = TipcRegistry::new();

/// Access the global TIPC registry.
///
/// # Safety
///
/// Single-threaded kernel use only; no concurrent mutation.
fn registry() -> &'static mut TipcRegistry {
    // SAFETY: single-threaded kernel context; no concurrent access.
    unsafe { &mut *core::ptr::addr_of_mut!(TIPC_REGISTRY) }
}

// ---------------------------------------------------------------------------
// Public syscall-level API
// ---------------------------------------------------------------------------

/// Create a new TIPC socket.
///
/// # Errors
///
/// `OutOfMemory` when the socket table is full.
pub fn tipc_socket(sock_type: TipcSocketType) -> Result<usize> {
    registry().socket(sock_type)
}

/// Close a TIPC socket.
///
/// # Errors
///
/// `InvalidArgument` for an invalid socket index.
pub fn tipc_close(sock: usize) -> Result<()> {
    registry().close(sock)
}

/// Bind a TIPC socket to a service range.
///
/// # Errors
///
/// * `InvalidArgument` — invalid socket, range, or scope.
/// * `OutOfMemory` — name-table is full.
pub fn tipc_bind(sock: usize, range: TipcServiceRange, scope: u32) -> Result<()> {
    registry().bind(sock, range, scope)
}

/// Unbind a TIPC socket from its service range.
///
/// If `range` is `None`, removes all bindings for the socket.
///
/// # Errors
///
/// `InvalidArgument` for an invalid socket index.
pub fn tipc_unbind(sock: usize, range: Option<TipcServiceRange>) -> Result<()> {
    registry().unbind(sock, range)
}

/// Connect a TIPC socket to a service address.
///
/// # Errors
///
/// * `InvalidArgument` — invalid socket or service.
/// * `NotFound` — no server bound to the address.
/// * `AlreadyExists` — already connected.
pub fn tipc_connect(sock: usize, service: TipcServiceAddr) -> Result<()> {
    registry().connect(sock, service)
}

/// Send a message from a TIPC socket.
///
/// # Errors
///
/// * `InvalidArgument` — invalid socket.
/// * `NotFound` — no destination for the service address.
/// * `OutOfMemory` — receiver queue full.
pub fn tipc_send(sock: usize, payload: &[u8], dest: Option<TipcServiceAddr>) -> Result<usize> {
    registry().send(sock, payload, dest)
}

/// Receive a message on a TIPC socket.
///
/// # Errors
///
/// * `InvalidArgument` — invalid socket.
/// * `WouldBlock` — no messages available.
pub fn tipc_recv(sock: usize, buf: &mut [u8]) -> Result<usize> {
    registry().recv(sock, buf)
}

/// Subscribe to topology events for a service range.
///
/// Returns a subscription sequence number used for
/// [`tipc_unsubscribe`].
///
/// # Errors
///
/// * `InvalidArgument` — invalid socket or range.
/// * `OutOfMemory` — subscription table full.
pub fn tipc_subscribe(sock: usize, range: TipcServiceRange) -> Result<u32> {
    registry().subscribe(sock, range)
}

/// Cancel a topology subscription.
///
/// # Errors
///
/// `NotFound` — no subscription with that sequence number.
pub fn tipc_unsubscribe(seq: u32) -> Result<()> {
    registry().unsubscribe(seq)
}

/// Look up sockets bound to a service address.
///
/// Returns the number of sockets written into `out`.
pub fn tipc_lookup(service: TipcServiceAddr, out: &mut [usize]) -> usize {
    registry().lookup(service, out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_registry() -> TipcRegistry {
        TipcRegistry::new()
    }

    #[test]
    fn test_socket_open_close() {
        let mut reg = make_registry();
        let fd = reg.socket(TipcSocketType::Rdm).unwrap();
        assert_eq!(reg.socket_count(), 1);
        reg.close(fd).unwrap();
        assert_eq!(reg.socket_count(), 0);
    }

    #[test]
    fn test_socket_table_full() {
        let mut reg = make_registry();
        for _ in 0..TIPC_MAX_SOCKETS {
            reg.socket(TipcSocketType::Rdm).unwrap();
        }
        assert!(reg.socket(TipcSocketType::Rdm).is_err());
    }

    #[test]
    fn test_service_range_validate() {
        assert!(TipcServiceRange::new(1234, 1, 10).validate().is_ok());
        assert!(TipcServiceRange::new(0, 1, 10).validate().is_err()); // type 0
        assert!(TipcServiceRange::new(1, 5, 3).validate().is_err()); // lower > upper
    }

    #[test]
    fn test_service_range_contains() {
        let range = TipcServiceRange::new(100, 10, 20);
        assert!(range.contains(&TipcServiceAddr::new(100, 10)));
        assert!(range.contains(&TipcServiceAddr::new(100, 15)));
        assert!(range.contains(&TipcServiceAddr::new(100, 20)));
        assert!(!range.contains(&TipcServiceAddr::new(100, 9)));
        assert!(!range.contains(&TipcServiceAddr::new(100, 21)));
        assert!(!range.contains(&TipcServiceAddr::new(999, 15))); // wrong type
    }

    #[test]
    fn test_bind_unbind() {
        let mut reg = make_registry();
        let fd = reg.socket(TipcSocketType::Rdm).unwrap();
        let range = TipcServiceRange::new(42, 1, 5);

        reg.bind(fd, range, TIPC_NODE_SCOPE).unwrap();
        assert_eq!(reg.binding_count(), 1);

        reg.unbind(fd, Some(range)).unwrap();
        assert_eq!(reg.binding_count(), 0);
    }

    #[test]
    fn test_bind_invalid_scope() {
        let mut reg = make_registry();
        let fd = reg.socket(TipcSocketType::Rdm).unwrap();
        let range = TipcServiceRange::single(10, 1);
        assert!(reg.bind(fd, range, 0).is_err());
        assert!(reg.bind(fd, range, 4).is_err());
    }

    #[test]
    fn test_lookup() {
        let mut reg = make_registry();
        let srv = reg.socket(TipcSocketType::Seqpacket).unwrap();
        reg.bind(srv, TipcServiceRange::new(7777, 1, 100), TIPC_NODE_SCOPE)
            .unwrap();

        let mut out = [0usize; 4];
        let found = reg.lookup(TipcServiceAddr::new(7777, 50), &mut out);
        assert_eq!(found, 1);
        assert_eq!(out[0], srv);

        // Out of range — nothing found.
        let found2 = reg.lookup(TipcServiceAddr::new(7777, 200), &mut out);
        assert_eq!(found2, 0);
    }

    #[test]
    fn test_connect_send_recv() {
        let mut reg = make_registry();
        let srv = reg.socket(TipcSocketType::Seqpacket).unwrap();
        let cli = reg.socket(TipcSocketType::Seqpacket).unwrap();

        reg.bind(srv, TipcServiceRange::single(1234, 1), TIPC_NODE_SCOPE)
            .unwrap();
        reg.connect(cli, TipcServiceAddr::new(1234, 1)).unwrap();

        // Client → server message.
        let payload = b"hello tipc";
        let sent = reg.send(cli, payload, None).unwrap();
        assert_eq!(sent, payload.len());

        let mut buf = [0u8; 64];
        let recvd = reg.recv(srv, &mut buf).unwrap();
        assert_eq!(recvd, payload.len());
        assert_eq!(&buf[..recvd], payload);
    }

    #[test]
    fn test_send_by_service_address() {
        let mut reg = make_registry();
        let srv = reg.socket(TipcSocketType::Rdm).unwrap();
        reg.bind(srv, TipcServiceRange::single(9999, 42), TIPC_NODE_SCOPE)
            .unwrap();

        let cli = reg.socket(TipcSocketType::Rdm).unwrap();
        let dest = TipcServiceAddr::new(9999, 42);
        reg.send(cli, b"ping", Some(dest)).unwrap();

        let mut buf = [0u8; 16];
        let n = reg.recv(srv, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"ping");
    }

    #[test]
    fn test_recv_empty_queue_would_block() {
        let mut reg = make_registry();
        let fd = reg.socket(TipcSocketType::Rdm).unwrap();
        let mut buf = [0u8; 16];
        assert!(reg.recv(fd, &mut buf).is_err());
    }

    #[test]
    fn test_connect_no_server() {
        let mut reg = make_registry();
        let cli = reg.socket(TipcSocketType::Seqpacket).unwrap();
        assert_eq!(
            reg.connect(cli, TipcServiceAddr::new(1111, 1)).unwrap_err(),
            Error::NotFound
        );
    }

    #[test]
    fn test_connect_already_connected() {
        let mut reg = make_registry();
        let srv = reg.socket(TipcSocketType::Seqpacket).unwrap();
        let cli = reg.socket(TipcSocketType::Seqpacket).unwrap();
        reg.bind(srv, TipcServiceRange::single(5555, 1), TIPC_NODE_SCOPE)
            .unwrap();
        reg.connect(cli, TipcServiceAddr::new(5555, 1)).unwrap();
        assert_eq!(
            reg.connect(cli, TipcServiceAddr::new(5555, 1)).unwrap_err(),
            Error::AlreadyExists
        );
    }

    #[test]
    fn test_subscribe_unsubscribe() {
        let mut reg = make_registry();
        let sub_fd = reg.socket(TipcSocketType::Rdm).unwrap();
        let range = TipcServiceRange::new(200, 1, 10);

        let seq = reg.subscribe(sub_fd, range).unwrap();
        assert_eq!(reg.subscription_count(), 1);

        reg.unsubscribe(seq).unwrap();
        assert_eq!(reg.subscription_count(), 0);
    }

    #[test]
    fn test_topology_event_on_bind() {
        let mut reg = make_registry();
        let sub_fd = reg.socket(TipcSocketType::Rdm).unwrap();
        let srv_fd = reg.socket(TipcSocketType::Seqpacket).unwrap();

        let range = TipcServiceRange::single(300, 7);
        reg.subscribe(sub_fd, range).unwrap();

        // Binding the server should trigger a topology event.
        reg.bind(srv_fd, TipcServiceRange::single(300, 7), TIPC_NODE_SCOPE)
            .unwrap();

        // The subscriber socket should have a message.
        let mut buf = [0u8; 16];
        let n = reg.recv(sub_fd, &mut buf).unwrap();
        assert_eq!(n, 16);

        // Check type field.
        let t = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let inst = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let is_pub = buf[8];
        assert_eq!(t, 300);
        assert_eq!(inst, 7);
        assert_eq!(is_pub, 1);
    }

    #[test]
    fn test_close_removes_bindings() {
        let mut reg = make_registry();
        let fd = reg.socket(TipcSocketType::Rdm).unwrap();
        reg.bind(fd, TipcServiceRange::single(400, 1), TIPC_NODE_SCOPE)
            .unwrap();
        assert_eq!(reg.binding_count(), 1);

        reg.close(fd).unwrap();
        assert_eq!(reg.binding_count(), 0);
        assert_eq!(reg.socket_count(), 0);
    }

    #[test]
    fn test_message_truncation() {
        let large = [0xABu8; TIPC_MAX_MSG_SIZE + 100];
        let msg = TipcMessage::new(0, &large, None);
        assert_eq!(msg.len, TIPC_MAX_MSG_SIZE);
    }

    #[test]
    fn test_unbind_all() {
        let mut reg = make_registry();
        let fd = reg.socket(TipcSocketType::Rdm).unwrap();
        reg.bind(fd, TipcServiceRange::new(50, 1, 5), TIPC_NODE_SCOPE)
            .unwrap();
        reg.bind(fd, TipcServiceRange::new(50, 6, 10), TIPC_NODE_SCOPE)
            .unwrap();
        assert_eq!(reg.binding_count(), 2);

        reg.unbind(fd, None).unwrap();
        assert_eq!(reg.binding_count(), 0);
    }
}
