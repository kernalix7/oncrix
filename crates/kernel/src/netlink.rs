// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Netlink socket protocol for kernel-userspace communication.
//!
//! Netlink is a Linux-style IPC mechanism used primarily for
//! transferring information between kernel and user-space
//! processes. It supports unicast, multicast, and kernel
//! notification delivery through a message-based protocol.
//!
//! # Protocol families
//!
//! - [`NETLINK_ROUTE`] — routing and link updates
//! - [`NETLINK_FIREWALL`] — firewall packet filtering
//! - [`NETLINK_KOBJECT_UEVENT`] — kernel object events (udev)
//! - [`NETLINK_GENERIC`] — generic extensible netlink
//!
//! # Design
//!
//! Each [`NetlinkSocket`] has a 16-slot ring buffer for
//! received messages. The [`NetlinkRegistry`] manages up to
//! [`MAX_NETLINK_SOCKETS`] sockets and provides unicast,
//! multicast, and kernel notification delivery.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Netlink protocol family: routing and link updates.
pub const NETLINK_ROUTE: i32 = 0;

/// Netlink protocol family: firewall.
pub const NETLINK_FIREWALL: i32 = 3;

/// Netlink protocol family: kernel object uevent.
pub const NETLINK_KOBJECT_UEVENT: i32 = 15;

/// Netlink protocol family: generic netlink.
pub const NETLINK_GENERIC: i32 = 16;

/// Netlink message flag: request.
pub const NLM_F_REQUEST: u16 = 1;

/// Netlink message flag: multi-part message.
pub const NLM_F_MULTI: u16 = 2;

/// Netlink message flag: acknowledgement requested.
pub const NLM_F_ACK: u16 = 4;

/// Netlink message flag: return complete table.
pub const NLM_F_ROOT: u16 = 0x100;

/// Netlink message flag: return matching entries.
pub const NLM_F_MATCH: u16 = 0x200;

/// Netlink message flag: dump (root | match).
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

/// Netlink message type: no-op.
pub const NLMSG_NOOP: u16 = 1;

/// Netlink message type: error.
pub const NLMSG_ERROR: u16 = 2;

/// Netlink message type: end of multi-part dump.
pub const NLMSG_DONE: u16 = 3;

/// Maximum number of netlink sockets.
pub const MAX_NETLINK_SOCKETS: usize = 64;

/// Maximum netlink message size in bytes.
pub const _MAX_NETLINK_MSG_SIZE: usize = 4096;

/// Maximum number of multicast groups.
pub const _NETLINK_GROUPS: u32 = 32;

/// Ring buffer capacity (number of message slots).
const RX_RING_SIZE: usize = 16;

/// Maximum payload size per ring buffer message.
const RX_MSG_SIZE: usize = 256;

// ---------------------------------------------------------------------------
// NlMsgHdr
// ---------------------------------------------------------------------------

/// Netlink message header (16 bytes, C-compatible layout).
///
/// Every netlink message begins with this fixed-size header,
/// followed by a type-specific payload. The `nlmsg_len` field
/// covers the header **plus** the payload.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct NlMsgHdr {
    /// Total message length including this header.
    pub nlmsg_len: u32,
    /// Message type (protocol-specific or one of `NLMSG_*`).
    pub nlmsg_type: u16,
    /// Flags (combination of `NLM_F_*`).
    pub nlmsg_flags: u16,
    /// Sequence number (for request/reply matching).
    pub nlmsg_seq: u32,
    /// Sending process port ID.
    pub nlmsg_pid: u32,
}

impl NlMsgHdr {
    /// Minimum valid message length (header only).
    const HEADER_SIZE: u32 = 16;

    /// Check whether this header describes a structurally valid
    /// message.
    ///
    /// A message is valid when `nlmsg_len` is at least as large
    /// as the header itself and does not exceed
    /// `_MAX_NETLINK_MSG_SIZE`.
    pub fn is_valid(&self) -> bool {
        self.nlmsg_len >= Self::HEADER_SIZE && (self.nlmsg_len as usize) <= _MAX_NETLINK_MSG_SIZE
    }
}

// ---------------------------------------------------------------------------
// NlAttr
// ---------------------------------------------------------------------------

/// Netlink attribute header (TLV-style).
///
/// Attributes follow the message header and carry typed
/// key-value data. The payload immediately follows this
/// 4-byte header; its length is `nla_len - 4`.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct NlAttr {
    /// Total attribute length (header + payload).
    pub nla_len: u16,
    /// Attribute type identifier.
    pub nla_type: u16,
}

// ---------------------------------------------------------------------------
// NetlinkFamily
// ---------------------------------------------------------------------------

/// Netlink protocol family identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum NetlinkFamily {
    /// Routing and link management.
    #[default]
    Route = 0,
    /// Firewall packet filtering.
    Firewall = 3,
    /// Kernel object uevents (udev).
    KobjectUevent = 15,
    /// Generic extensible netlink.
    Generic = 16,
}

impl NetlinkFamily {
    /// Convert a raw `i32` to a [`NetlinkFamily`].
    ///
    /// Returns `InvalidArgument` for unrecognised values.
    pub fn from_i32(v: i32) -> Result<Self> {
        match v {
            0 => Ok(Self::Route),
            3 => Ok(Self::Firewall),
            15 => Ok(Self::KobjectUevent),
            16 => Ok(Self::Generic),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ---------------------------------------------------------------------------
// NetlinkMessage
// ---------------------------------------------------------------------------

/// A single buffered netlink message in the receive ring.
#[derive(Clone, Copy)]
pub struct NetlinkMessage {
    /// Raw message data.
    data: [u8; RX_MSG_SIZE],
    /// Number of valid bytes in `data`.
    len: usize,
}

impl NetlinkMessage {
    /// Create an empty message.
    const fn empty() -> Self {
        Self {
            data: [0u8; RX_MSG_SIZE],
            len: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// NetlinkSocket
// ---------------------------------------------------------------------------

/// A single netlink socket with a per-socket receive ring buffer.
///
/// Each socket belongs to a [`NetlinkFamily`] and may subscribe
/// to multicast groups via a bitmask. Incoming messages are
/// stored in a fixed-size ring buffer (`RX_RING_SIZE` slots of
/// `RX_MSG_SIZE` bytes each).
pub struct NetlinkSocket {
    /// Unique socket identifier.
    id: u32,
    /// Process (port) identifier of the owning process.
    pid: u32,
    /// Protocol family this socket belongs to.
    family: NetlinkFamily,
    /// Multicast group subscription bitmask.
    groups: u32,
    /// Receive ring buffer.
    rx_queue: [NetlinkMessage; RX_RING_SIZE],
    /// Head index of the ring buffer (next read position).
    rx_head: usize,
    /// Tail index of the ring buffer (next write position).
    rx_tail: usize,
    /// Number of messages currently queued.
    rx_count: usize,
    /// Whether the socket is in use.
    active: bool,
}

impl NetlinkSocket {
    /// Create an inactive (empty) socket.
    const fn empty() -> Self {
        Self {
            id: 0,
            pid: 0,
            family: NetlinkFamily::Route,
            groups: 0,
            rx_queue: [NetlinkMessage::empty(); RX_RING_SIZE],
            rx_head: 0,
            rx_tail: 0,
            rx_count: 0,
            active: false,
        }
    }

    /// Enqueue a message into the receive ring buffer.
    ///
    /// Returns `WouldBlock` when the ring is full.
    fn enqueue(&mut self, data: &[u8]) -> Result<()> {
        if self.rx_count >= RX_RING_SIZE {
            return Err(Error::WouldBlock);
        }
        let copy_len = data.len().min(RX_MSG_SIZE);
        let msg = &mut self.rx_queue[self.rx_tail];
        msg.data[..copy_len].copy_from_slice(&data[..copy_len]);
        msg.len = copy_len;
        self.rx_tail = (self.rx_tail + 1) % RX_RING_SIZE;
        self.rx_count += 1;
        Ok(())
    }

    /// Dequeue a message from the receive ring buffer into `buf`.
    ///
    /// Returns the number of bytes copied, or `WouldBlock` when
    /// the ring is empty.
    fn dequeue(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.rx_count == 0 {
            return Err(Error::WouldBlock);
        }
        let msg = &self.rx_queue[self.rx_head];
        let copy_len = msg.len.min(buf.len());
        buf[..copy_len].copy_from_slice(&msg.data[..copy_len]);
        self.rx_head = (self.rx_head + 1) % RX_RING_SIZE;
        self.rx_count -= 1;
        Ok(copy_len)
    }
}

// ---------------------------------------------------------------------------
// NetlinkRegistry
// ---------------------------------------------------------------------------

/// Central registry for all netlink sockets.
///
/// Manages creation, lookup, message delivery, and teardown
/// of up to [`MAX_NETLINK_SOCKETS`] sockets. Supports unicast,
/// multicast, and kernel-originated notifications.
pub struct NetlinkRegistry {
    /// Socket table.
    sockets: [NetlinkSocket; MAX_NETLINK_SOCKETS],
    /// Monotonically increasing ID counter.
    next_id: u32,
    /// Number of active sockets.
    count: usize,
}

impl Default for NetlinkRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl NetlinkRegistry {
    /// Create a new, empty registry.
    pub const fn new() -> Self {
        Self {
            sockets: [const { NetlinkSocket::empty() }; MAX_NETLINK_SOCKETS],
            next_id: 1,
            count: 0,
        }
    }

    /// Return the number of active sockets.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` when no sockets are active.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Create a new netlink socket for the given family and PID.
    ///
    /// Returns the new socket's unique ID, or `OutOfMemory` when
    /// the socket table is full.
    pub fn create(&mut self, family: NetlinkFamily, pid: u32) -> Result<u32> {
        if self.count >= MAX_NETLINK_SOCKETS {
            return Err(Error::OutOfMemory);
        }
        let slot = self
            .sockets
            .iter()
            .position(|s| !s.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let sock = &mut self.sockets[slot];
        *sock = NetlinkSocket::empty();
        sock.id = id;
        sock.pid = pid;
        sock.family = family;
        sock.active = true;

        self.count += 1;
        Ok(id)
    }

    /// Close a netlink socket by its ID.
    ///
    /// Returns `NotFound` if the socket does not exist.
    pub fn close(&mut self, id: u32) -> Result<()> {
        let sock = self.find_mut(id)?;
        sock.active = false;
        self.count -= 1;
        Ok(())
    }

    /// Bind a socket to one or more multicast groups.
    ///
    /// The `groups` bitmask is OR-ed into the socket's existing
    /// group subscriptions.
    pub fn bind(&mut self, id: u32, groups: u32) -> Result<()> {
        let sock = self.find_mut(id)?;
        sock.groups |= groups;
        Ok(())
    }

    /// Send a unicast message to the socket identified by
    /// `dst_pid`.
    ///
    /// The sending socket (identified by `id`) must be active.
    /// If no socket with `dst_pid` exists, returns `NotFound`.
    /// Message data is truncated to `RX_MSG_SIZE` bytes.
    pub fn sendmsg(&mut self, id: u32, data: &[u8], dst_pid: u32) -> Result<()> {
        // Validate sender exists.
        if !self.sockets.iter().any(|s| s.active && s.id == id) {
            return Err(Error::NotFound);
        }
        if data.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let dst = self
            .sockets
            .iter_mut()
            .find(|s| s.active && s.pid == dst_pid)
            .ok_or(Error::NotFound)?;
        dst.enqueue(data)
    }

    /// Receive the next queued message from a socket.
    ///
    /// Copies up to `buf.len()` bytes into `buf` and returns the
    /// number of bytes copied. Returns `WouldBlock` when no
    /// messages are available.
    pub fn recvmsg(&mut self, id: u32, buf: &mut [u8]) -> Result<usize> {
        let sock = self.find_mut(id)?;
        sock.dequeue(buf)
    }

    /// Deliver a message to all sockets of the given `family`
    /// that are subscribed to `group`.
    ///
    /// Sockets whose receive ring is full silently drop the
    /// message.
    pub fn multicast(&mut self, family: NetlinkFamily, group: u32, data: &[u8]) {
        for sock in &mut self.sockets {
            if sock.active && sock.family == family && (sock.groups & group) != 0 {
                let _ = sock.enqueue(data);
            }
        }
    }

    /// Send a kernel-originated notification to all sockets of
    /// the specified family.
    ///
    /// Builds a minimal [`NlMsgHdr`] (pid = 0, seq = 0) and
    /// enqueues it to every active socket in the family. Sockets
    /// whose ring buffer is full silently drop the notification.
    pub fn kernel_notify(&mut self, family: NetlinkFamily, msg_type: u16, data: &[u8]) {
        let payload_len = data
            .len()
            .min(RX_MSG_SIZE - core::mem::size_of::<NlMsgHdr>());
        let total_len = core::mem::size_of::<NlMsgHdr>() + payload_len;

        let mut buf = [0u8; RX_MSG_SIZE];
        let hdr = NlMsgHdr {
            nlmsg_len: total_len as u32,
            nlmsg_type: msg_type,
            nlmsg_flags: 0,
            nlmsg_seq: 0,
            nlmsg_pid: 0,
        };
        let hdr_bytes: [u8; 16] = unsafe {
            // SAFETY: NlMsgHdr is repr(C), 16 bytes, and
            // contains only integer fields with no padding
            // concerns — transmuting to a byte array is safe.
            core::mem::transmute(hdr)
        };
        let hdr_size = core::mem::size_of::<NlMsgHdr>();
        buf[..hdr_size].copy_from_slice(&hdr_bytes);
        buf[hdr_size..hdr_size + payload_len].copy_from_slice(&data[..payload_len]);

        for sock in &mut self.sockets {
            if sock.active && sock.family == family {
                let _ = sock.enqueue(&buf[..total_len]);
            }
        }
    }

    /// Find an active socket by ID (mutable).
    fn find_mut(&mut self, id: u32) -> Result<&mut NetlinkSocket> {
        self.sockets
            .iter_mut()
            .find(|s| s.active && s.id == id)
            .ok_or(Error::NotFound)
    }
}
