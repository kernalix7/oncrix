// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Netlink socket protocol for kernel-userspace communication.
//!
//! Netlink provides a datagram-oriented socket protocol for passing
//! messages between the kernel and user-space processes, and between
//! user-space processes. It is the primary mechanism in Linux for
//! network configuration, device events, audit logging, and similar
//! kernel-to-user notifications.
//!
//! # Message structure
//!
//! Every Netlink message starts with a [`NlMsgHdr`] header followed by
//! a payload.  Payload attributes use the TLV (Type-Length-Value)
//! format via [`NlAttr`] (Netlink Attribute).
//!
//! # Families
//!
//! | Family | Description |
//! |--------|-------------|
//! | `NETLINK_ROUTE` | Routing and link configuration |
//! | `NETLINK_FIREWALL` | Firewall/netfilter events |
//! | `NETLINK_SOCK_DIAG` | Socket diagnostics |
//! | `NETLINK_NETFILTER` | Netfilter subsystem |
//! | `NETLINK_KOBJECT_UEVENT` | Kernel object uevents |
//! | `NETLINK_GENERIC` | Generic netlink (extensible) |
//! | `NETLINK_AUDIT` | Audit subsystem |
//!
//! # References
//!
//! - Linux: `net/netlink/`, `include/uapi/linux/netlink.h`
//! - RFC 3549: Linux Netlink as an IP Services Protocol

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum Netlink message payload size.
const NLMSG_MAX_PAYLOAD: usize = 4096;

/// Maximum number of Netlink sockets.
const MAX_NETLINK_SOCKETS: usize = 64;

/// Maximum multicast groups per socket.
const MAX_MULTICAST_GROUPS: usize = 32;

/// Maximum number of attributes per message.
const MAX_ATTRS_PER_MSG: usize = 32;

/// Maximum queued messages per socket.
const MAX_QUEUED_MESSAGES: usize = 64;

/// Netlink header alignment (4 bytes, matching `NLMSG_ALIGN`).
const NLMSG_ALIGNTO: usize = 4;

// ---------------------------------------------------------------------------
// Netlink families
// ---------------------------------------------------------------------------

/// Routing/link messages (ip route, ip link, etc.).
pub const NETLINK_ROUTE: u16 = 0;

/// Firewall (legacy, replaced by NETFILTER).
pub const NETLINK_FIREWALL: u16 = 3;

/// Socket diagnostics (ss, netstat).
pub const NETLINK_SOCK_DIAG: u16 = 4;

/// Netfilter subsystem.
pub const NETLINK_NETFILTER: u16 = 12;

/// Kernel object uevents (udev).
pub const NETLINK_KOBJECT_UEVENT: u16 = 15;

/// Generic netlink (extensible multiplexer).
pub const NETLINK_GENERIC: u16 = 16;

/// Audit subsystem.
pub const NETLINK_AUDIT: u16 = 9;

/// SELinux events.
pub const NETLINK_SELINUX: u16 = 7;

/// SCSI transport events.
pub const NETLINK_SCSITRANSPORT: u16 = 18;

/// Connector (kernel/userspace notification).
pub const NETLINK_CONNECTOR: u16 = 11;

// ---------------------------------------------------------------------------
// Standard message types
// ---------------------------------------------------------------------------

/// No-op message.
pub const NLMSG_NOOP: u16 = 0x01;

/// Error response / ACK.
pub const NLMSG_ERROR: u16 = 0x02;

/// End of multipart message sequence.
pub const NLMSG_DONE: u16 = 0x03;

/// Data lost (overrun).
pub const NLMSG_OVERRUN: u16 = 0x04;

/// Minimum type number for protocol-specific messages.
pub const NLMSG_MIN_TYPE: u16 = 0x10;

// ---------------------------------------------------------------------------
// Message flags
// ---------------------------------------------------------------------------

/// Request message (from user to kernel).
pub const NLM_F_REQUEST: u16 = 0x01;

/// Multipart message.
pub const NLM_F_MULTI: u16 = 0x02;

/// Request ACK on success.
pub const NLM_F_ACK: u16 = 0x04;

/// Echo this request back.
pub const NLM_F_ECHO: u16 = 0x08;

/// Dump request — return all entries.
pub const NLM_F_DUMP: u16 = 0x0300;

/// GET: return the root of the tree.
pub const NLM_F_ROOT: u16 = 0x0100;

/// GET: return all matching entries.
pub const NLM_F_MATCH: u16 = 0x0200;

/// NEW: create if it doesn't exist.
pub const NLM_F_CREATE: u16 = 0x0400;

/// NEW: fail if it already exists (with CREATE).
pub const NLM_F_EXCL: u16 = 0x0200;

/// NEW: replace existing entry.
pub const NLM_F_REPLACE: u16 = 0x0100;

/// NEW: append to end of list.
pub const NLM_F_APPEND: u16 = 0x0800;

// ---------------------------------------------------------------------------
// NlMsgHdr — Netlink message header
// ---------------------------------------------------------------------------

/// Netlink message header.
///
/// Every Netlink message starts with this 16-byte header. The `len`
/// field includes the header itself.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NlMsgHdr {
    /// Total message length (including header).
    pub nlmsg_len: u32,
    /// Message type.
    pub nlmsg_type: u16,
    /// Message flags.
    pub nlmsg_flags: u16,
    /// Sequence number.
    pub nlmsg_seq: u32,
    /// Sending port ID (0 = kernel).
    pub nlmsg_pid: u32,
}

impl NlMsgHdr {
    /// Header size in bytes.
    pub const SIZE: usize = 16;

    /// Create a new header.
    pub const fn new(msg_type: u16, flags: u16, seq: u32, pid: u32, payload_len: u32) -> Self {
        Self {
            nlmsg_len: Self::SIZE as u32 + payload_len,
            nlmsg_type: msg_type,
            nlmsg_flags: flags,
            nlmsg_seq: seq,
            nlmsg_pid: pid,
        }
    }

    /// Return the payload length (total length minus header).
    pub const fn payload_len(&self) -> u32 {
        if self.nlmsg_len > Self::SIZE as u32 {
            self.nlmsg_len - Self::SIZE as u32
        } else {
            0
        }
    }

    /// Validate the header.
    pub const fn is_valid(&self) -> bool {
        self.nlmsg_len >= Self::SIZE as u32
    }

    /// Return `true` if this is a request message.
    pub const fn is_request(&self) -> bool {
        self.nlmsg_flags & NLM_F_REQUEST != 0
    }

    /// Return `true` if ACK is requested.
    pub const fn wants_ack(&self) -> bool {
        self.nlmsg_flags & NLM_F_ACK != 0
    }

    /// Return `true` if this is a dump request.
    pub const fn is_dump(&self) -> bool {
        self.nlmsg_flags & NLM_F_DUMP == NLM_F_DUMP
    }

    /// Return `true` if this is a multipart message.
    pub const fn is_multipart(&self) -> bool {
        self.nlmsg_flags & NLM_F_MULTI != 0
    }
}

// Compile-time check.
const _: () = {
    assert!(core::mem::size_of::<NlMsgHdr>() == NlMsgHdr::SIZE);
};

// ---------------------------------------------------------------------------
// NlAttr — Netlink attribute (TLV)
// ---------------------------------------------------------------------------

/// Netlink attribute header (NLA).
///
/// Attributes carry typed data within a Netlink message payload.
/// Each attribute has a 4-byte header followed by the value.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NlAttr {
    /// Total attribute length (header + value).
    pub nla_len: u16,
    /// Attribute type.
    pub nla_type: u16,
}

impl NlAttr {
    /// NLA header size.
    pub const HEADER_SIZE: usize = 4;

    /// Create a new attribute header.
    pub const fn new(attr_type: u16, value_len: u16) -> Self {
        Self {
            nla_len: Self::HEADER_SIZE as u16 + value_len,
            nla_type: attr_type,
        }
    }

    /// Return the value length.
    pub const fn value_len(&self) -> u16 {
        if self.nla_len > Self::HEADER_SIZE as u16 {
            self.nla_len - Self::HEADER_SIZE as u16
        } else {
            0
        }
    }

    /// Return the aligned total length (padded to 4-byte boundary).
    pub const fn aligned_len(&self) -> usize {
        let len = self.nla_len as usize;
        (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
    }
}

// ---------------------------------------------------------------------------
// NlErrMsg — Netlink error/ACK response
// ---------------------------------------------------------------------------

/// Netlink error response message.
///
/// Sent in response to a request when an error occurs, or as an ACK
/// (with `error == 0`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NlErrMsg {
    /// Error code (negative errno, or 0 for ACK).
    pub error: i32,
    /// Header of the original message that caused the error.
    pub msg: NlMsgHdr,
}

impl NlErrMsg {
    /// Create an ACK response (error == 0).
    pub const fn ack(original: NlMsgHdr) -> Self {
        Self {
            error: 0,
            msg: original,
        }
    }

    /// Create an error response.
    pub const fn error(code: i32, original: NlMsgHdr) -> Self {
        Self {
            error: code,
            msg: original,
        }
    }

    /// Return `true` if this is an ACK (no error).
    pub const fn is_ack(&self) -> bool {
        self.error == 0
    }
}

// ---------------------------------------------------------------------------
// NetlinkMessage — a queued message
// ---------------------------------------------------------------------------

/// A Netlink message in the queue.
///
/// Contains the header and a payload buffer.
pub struct NetlinkMessage {
    /// Message header.
    pub header: NlMsgHdr,
    /// Payload data.
    pub payload: [u8; NLMSG_MAX_PAYLOAD],
    /// Actual payload length.
    pub payload_len: usize,
    /// Source port ID.
    pub src_pid: u32,
    /// Whether this slot is occupied.
    pub occupied: bool,
}

impl NetlinkMessage {
    /// Create an empty message.
    const fn new() -> Self {
        Self {
            header: NlMsgHdr {
                nlmsg_len: 0,
                nlmsg_type: 0,
                nlmsg_flags: 0,
                nlmsg_seq: 0,
                nlmsg_pid: 0,
            },
            payload: [0u8; NLMSG_MAX_PAYLOAD],
            payload_len: 0,
            src_pid: 0,
            occupied: false,
        }
    }
}

// ---------------------------------------------------------------------------
// NetlinkSocket — a single socket
// ---------------------------------------------------------------------------

/// A Netlink socket instance.
///
/// Each socket is bound to a specific Netlink family and port ID.
pub struct NetlinkSocket {
    /// Unique socket ID.
    id: u64,
    /// Netlink protocol family.
    family: u16,
    /// Port ID (unique per family).
    port_id: u32,
    /// PID of the owning process.
    owner_pid: u64,
    /// Multicast group memberships (bitmask).
    multicast_groups: u32,
    /// Whether this socket is active.
    active: bool,
    /// Receive queue (ring buffer).
    recv_queue: [NetlinkMessage; MAX_QUEUED_MESSAGES],
    /// Receive queue head.
    recv_head: usize,
    /// Receive queue tail.
    recv_tail: usize,
    /// Receive queue count.
    recv_count: usize,
    /// Sequence number counter.
    next_seq: u32,
    /// Non-blocking flag.
    nonblock: bool,
}

impl NetlinkSocket {
    /// Create an inactive socket.
    const fn new() -> Self {
        Self {
            id: 0,
            family: 0,
            port_id: 0,
            owner_pid: 0,
            multicast_groups: 0,
            active: false,
            recv_queue: [const { NetlinkMessage::new() }; MAX_QUEUED_MESSAGES],
            recv_head: 0,
            recv_tail: 0,
            recv_count: 0,
            next_seq: 1,
            nonblock: false,
        }
    }

    /// Return the socket ID.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Return the Netlink family.
    pub const fn family(&self) -> u16 {
        self.family
    }

    /// Return the port ID.
    pub const fn port_id(&self) -> u32 {
        self.port_id
    }

    /// Return the owner PID.
    pub const fn owner_pid(&self) -> u64 {
        self.owner_pid
    }

    /// Return multicast group memberships.
    pub const fn multicast_groups(&self) -> u32 {
        self.multicast_groups
    }

    /// Return `true` if this socket is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Return the number of messages in the receive queue.
    pub const fn recv_queue_len(&self) -> usize {
        self.recv_count
    }

    /// Return `true` if the receive queue is empty.
    pub const fn recv_queue_empty(&self) -> bool {
        self.recv_count == 0
    }

    /// Return the next sequence number and advance.
    fn next_sequence(&mut self) -> u32 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        seq
    }

    /// Enqueue a message into the receive queue.
    fn enqueue(&mut self, header: NlMsgHdr, payload: &[u8], src_pid: u32) -> Result<()> {
        if self.recv_count >= MAX_QUEUED_MESSAGES {
            return Err(Error::OutOfMemory);
        }
        let slot = &mut self.recv_queue[self.recv_tail];
        slot.header = header;
        let copy_len = payload.len().min(NLMSG_MAX_PAYLOAD);
        slot.payload[..copy_len].copy_from_slice(&payload[..copy_len]);
        slot.payload_len = copy_len;
        slot.src_pid = src_pid;
        slot.occupied = true;
        self.recv_tail = (self.recv_tail + 1) % MAX_QUEUED_MESSAGES;
        self.recv_count += 1;
        Ok(())
    }

    /// Dequeue a message from the receive queue.
    fn dequeue(&mut self) -> Result<(NlMsgHdr, usize)> {
        if self.recv_count == 0 {
            if self.nonblock {
                return Err(Error::WouldBlock);
            }
            return Err(Error::WouldBlock);
        }
        let slot = &self.recv_queue[self.recv_head];
        let header = slot.header;
        let payload_len = slot.payload_len;
        self.recv_head = (self.recv_head + 1) % MAX_QUEUED_MESSAGES;
        self.recv_count -= 1;
        Ok((header, payload_len))
    }
}

// ---------------------------------------------------------------------------
// NetlinkRegistry
// ---------------------------------------------------------------------------

/// Registry managing Netlink sockets.
pub struct NetlinkRegistry {
    /// Socket slots.
    sockets: [NetlinkSocket; MAX_NETLINK_SOCKETS],
    /// Next socket ID.
    next_id: u64,
    /// Number of active sockets.
    count: usize,
    /// Next port ID to assign.
    next_port_id: u32,
}

impl NetlinkRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            sockets: [const { NetlinkSocket::new() }; MAX_NETLINK_SOCKETS],
            next_id: 1,
            count: 0,
            next_port_id: 1000,
        }
    }

    /// Return the number of active sockets.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return `true` if no sockets are active.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    // ---------------------------------------------------------------
    // Lookup helpers
    // ---------------------------------------------------------------

    /// Find an active socket by ID (shared reference).
    fn find(&self, id: u64) -> Result<&NetlinkSocket> {
        self.sockets
            .iter()
            .find(|s| s.active && s.id == id)
            .ok_or(Error::NotFound)
    }

    /// Find an active socket by ID (mutable reference).
    fn find_mut(&mut self, id: u64) -> Result<&mut NetlinkSocket> {
        self.sockets
            .iter_mut()
            .find(|s| s.active && s.id == id)
            .ok_or(Error::NotFound)
    }

    // ---------------------------------------------------------------
    // Socket lifecycle
    // ---------------------------------------------------------------

    /// Create a new Netlink socket.
    ///
    /// Returns the socket ID on success.
    pub fn create(&mut self, family: u16, pid: u64, nonblock: bool) -> Result<u64> {
        let idx = self
            .sockets
            .iter()
            .position(|s| !s.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let port_id = self.next_port_id;
        self.next_port_id = self.next_port_id.wrapping_add(1);

        let slot = &mut self.sockets[idx];
        slot.id = id;
        slot.family = family;
        slot.port_id = port_id;
        slot.owner_pid = pid;
        slot.multicast_groups = 0;
        slot.active = true;
        slot.recv_head = 0;
        slot.recv_tail = 0;
        slot.recv_count = 0;
        slot.next_seq = 1;
        slot.nonblock = nonblock;

        self.count += 1;
        Ok(id)
    }

    /// Close a Netlink socket.
    pub fn close(&mut self, id: u64) -> Result<()> {
        let sock = self.find_mut(id)?;
        sock.active = false;
        sock.recv_count = 0;
        sock.recv_head = 0;
        sock.recv_tail = 0;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    // ---------------------------------------------------------------
    // Multicast groups
    // ---------------------------------------------------------------

    /// Join a multicast group.
    pub fn join_group(&mut self, id: u64, group: u32) -> Result<()> {
        if group == 0 || group > MAX_MULTICAST_GROUPS as u32 {
            return Err(Error::InvalidArgument);
        }
        let sock = self.find_mut(id)?;
        sock.multicast_groups |= 1 << (group - 1);
        Ok(())
    }

    /// Leave a multicast group.
    pub fn leave_group(&mut self, id: u64, group: u32) -> Result<()> {
        if group == 0 || group > MAX_MULTICAST_GROUPS as u32 {
            return Err(Error::InvalidArgument);
        }
        let sock = self.find_mut(id)?;
        sock.multicast_groups &= !(1 << (group - 1));
        Ok(())
    }

    // ---------------------------------------------------------------
    // Send / receive
    // ---------------------------------------------------------------

    /// Send a message to a specific socket by ID.
    pub fn send_to(
        &mut self,
        dst_id: u64,
        msg_type: u16,
        flags: u16,
        payload: &[u8],
        src_pid: u32,
    ) -> Result<()> {
        if payload.len() > NLMSG_MAX_PAYLOAD {
            return Err(Error::InvalidArgument);
        }

        let dst = self.find_mut(dst_id)?;
        let seq = dst.next_sequence();
        let header = NlMsgHdr::new(msg_type, flags, seq, src_pid, payload.len() as u32);
        dst.enqueue(header, payload, src_pid)
    }

    /// Send an ACK response to a socket.
    pub fn send_ack(&mut self, dst_id: u64, original: &NlMsgHdr) -> Result<()> {
        let err_msg = NlErrMsg::ack(*original);
        let payload_bytes = err_msg.error.to_ne_bytes();
        let dst = self.find_mut(dst_id)?;
        let header = NlMsgHdr::new(NLMSG_ERROR, 0, original.nlmsg_seq, 0, 4);
        dst.enqueue(header, &payload_bytes, 0)
    }

    /// Send an error response to a socket.
    pub fn send_error(&mut self, dst_id: u64, original: &NlMsgHdr, errno: i32) -> Result<()> {
        let payload_bytes = errno.to_ne_bytes();
        let dst = self.find_mut(dst_id)?;
        let header = NlMsgHdr::new(NLMSG_ERROR, 0, original.nlmsg_seq, 0, 4);
        dst.enqueue(header, &payload_bytes, 0)
    }

    /// Receive a message from a socket.
    ///
    /// Returns the message header and the payload length.
    pub fn recv(&mut self, id: u64) -> Result<(NlMsgHdr, usize)> {
        let sock = self.find_mut(id)?;
        sock.dequeue()
    }

    /// Broadcast a message to all sockets in a multicast group.
    ///
    /// Returns the number of sockets that received the message.
    pub fn multicast(
        &mut self,
        family: u16,
        group: u32,
        msg_type: u16,
        payload: &[u8],
        src_pid: u32,
    ) -> Result<u32> {
        if group == 0 || group > MAX_MULTICAST_GROUPS as u32 {
            return Err(Error::InvalidArgument);
        }
        if payload.len() > NLMSG_MAX_PAYLOAD {
            return Err(Error::InvalidArgument);
        }

        let group_bit = 1u32 << (group - 1);
        let mut delivered = 0u32;

        // Collect target socket indices first to avoid borrow issues.
        let mut targets: [usize; MAX_NETLINK_SOCKETS] = [0; MAX_NETLINK_SOCKETS];
        let mut target_count = 0usize;
        for (i, sock) in self.sockets.iter().enumerate() {
            if sock.active && sock.family == family && (sock.multicast_groups & group_bit) != 0 {
                targets[target_count] = i;
                target_count += 1;
            }
        }

        for idx in 0..target_count {
            let i = targets[idx];
            let sock = &mut self.sockets[i];
            let seq = sock.next_sequence();
            let header = NlMsgHdr::new(msg_type, NLM_F_MULTI, seq, src_pid, payload.len() as u32);
            if sock.enqueue(header, payload, src_pid).is_ok() {
                delivered += 1;
            }
        }

        Ok(delivered)
    }

    /// Send a dump-done message to indicate end of dump sequence.
    pub fn send_dump_done(&mut self, dst_id: u64, seq: u32) -> Result<()> {
        let dst = self.find_mut(dst_id)?;
        let header = NlMsgHdr::new(NLMSG_DONE, NLM_F_MULTI, seq, 0, 0);
        dst.enqueue(header, &[], 0)
    }

    /// Poll a socket for readiness.
    ///
    /// Returns POLLIN (0x01) if messages are available.
    pub fn poll(&self, id: u64) -> Result<u32> {
        let sock = self.find(id)?;
        if sock.recv_count > 0 { Ok(0x01) } else { Ok(0) }
    }

    /// Close all sockets owned by the given PID.
    pub fn cleanup_pid(&mut self, pid: u64) {
        for sock in self.sockets.iter_mut() {
            if sock.active && sock.owner_pid == pid {
                sock.active = false;
                sock.recv_count = 0;
                sock.recv_head = 0;
                sock.recv_tail = 0;
                self.count = self.count.saturating_sub(1);
            }
        }
    }
}

impl Default for NetlinkRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// NLA parsing helpers
// ---------------------------------------------------------------------------

/// Parse the first NLA (Netlink Attribute) from a payload buffer.
///
/// Returns the attribute header and the offset to the next attribute.
/// Returns `None` if the buffer is too small for an NLA header.
pub fn parse_nla(buf: &[u8]) -> Option<(NlAttr, usize)> {
    if buf.len() < NlAttr::HEADER_SIZE {
        return None;
    }
    let nla_len = u16::from_ne_bytes([buf[0], buf[1]]);
    let nla_type = u16::from_ne_bytes([buf[2], buf[3]]);
    let attr = NlAttr { nla_len, nla_type };
    if (nla_len as usize) < NlAttr::HEADER_SIZE || (nla_len as usize) > buf.len() {
        return None;
    }
    Some((attr, attr.aligned_len()))
}

/// Iterate over all NLA attributes in a payload buffer.
///
/// Calls `callback` for each valid attribute found, passing the
/// attribute header and a slice over the attribute value bytes.
/// Returns the total number of attributes parsed.
pub fn for_each_nla<F>(buf: &[u8], mut callback: F) -> usize
where
    F: FnMut(&NlAttr, &[u8]),
{
    let mut offset = 0usize;
    let mut count = 0usize;

    while offset < buf.len() {
        let remaining = &buf[offset..];
        if let Some((attr, aligned)) = parse_nla(remaining) {
            let value_start = NlAttr::HEADER_SIZE;
            let value_end = attr.nla_len as usize;
            if value_end <= remaining.len() {
                callback(&attr, &remaining[value_start..value_end]);
                count += 1;
            }
            offset += aligned;
        } else {
            break;
        }
    }

    count
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_size() {
        assert_eq!(core::mem::size_of::<NlMsgHdr>(), 16);
    }

    #[test]
    fn header_payload_len() {
        let h = NlMsgHdr::new(NLMSG_NOOP, 0, 1, 0, 100);
        assert_eq!(h.payload_len(), 100);
        assert!(h.is_valid());
    }

    #[test]
    fn header_flags() {
        let h = NlMsgHdr::new(0, NLM_F_REQUEST | NLM_F_ACK, 1, 0, 0);
        assert!(h.is_request());
        assert!(h.wants_ack());
        assert!(!h.is_dump());
    }

    #[test]
    fn nla_alignment() {
        let a = NlAttr::new(1, 5);
        assert_eq!(a.nla_len, 9); // 4 header + 5 value
        assert_eq!(a.aligned_len(), 12); // Padded to 4-byte boundary.
    }

    #[test]
    fn nla_value_len() {
        let a = NlAttr::new(1, 10);
        assert_eq!(a.value_len(), 10);
    }

    #[test]
    fn create_socket() {
        let mut r = NetlinkRegistry::new();
        let id = r.create(NETLINK_ROUTE, 1, false);
        assert!(id.is_ok());
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn close_socket() {
        let mut r = NetlinkRegistry::new();
        let id = r.create(NETLINK_ROUTE, 1, false).unwrap();
        assert_eq!(r.close(id), Ok(()));
        assert_eq!(r.count(), 0);
    }

    #[test]
    fn send_and_recv() {
        let mut r = NetlinkRegistry::new();
        let id = r.create(NETLINK_ROUTE, 1, true).unwrap();
        let payload = [1u8, 2, 3, 4];
        let _ = r.send_to(id, NLMSG_MIN_TYPE, NLM_F_REQUEST, &payload, 0);
        let (hdr, len) = r.recv(id).unwrap();
        assert_eq!(hdr.nlmsg_type, NLMSG_MIN_TYPE);
        assert_eq!(len, 4);
    }

    #[test]
    fn recv_empty_wouldblock() {
        let mut r = NetlinkRegistry::new();
        let id = r.create(NETLINK_ROUTE, 1, true).unwrap();
        assert_eq!(r.recv(id), Err(Error::WouldBlock));
    }

    #[test]
    fn multicast_group() {
        let mut r = NetlinkRegistry::new();
        let id1 = r.create(NETLINK_ROUTE, 1, false).unwrap();
        let id2 = r.create(NETLINK_ROUTE, 2, false).unwrap();
        let _ = r.join_group(id1, 1);
        let _ = r.join_group(id2, 1);

        let delivered = r
            .multicast(NETLINK_ROUTE, 1, NLMSG_MIN_TYPE, &[0xAA], 0)
            .unwrap();
        assert_eq!(delivered, 2);

        // Both should have a message.
        assert!(r.recv(id1).is_ok());
        assert!(r.recv(id2).is_ok());
    }

    #[test]
    fn leave_group() {
        let mut r = NetlinkRegistry::new();
        let id = r.create(NETLINK_ROUTE, 1, false).unwrap();
        let _ = r.join_group(id, 1);
        let _ = r.leave_group(id, 1);

        let delivered = r
            .multicast(NETLINK_ROUTE, 1, NLMSG_MIN_TYPE, &[0xBB], 0)
            .unwrap();
        assert_eq!(delivered, 0);
    }

    #[test]
    fn invalid_group_rejected() {
        let mut r = NetlinkRegistry::new();
        let id = r.create(NETLINK_ROUTE, 1, false).unwrap();
        assert_eq!(r.join_group(id, 0), Err(Error::InvalidArgument));
        assert_eq!(r.join_group(id, 99), Err(Error::InvalidArgument));
    }

    #[test]
    fn send_ack() {
        let mut r = NetlinkRegistry::new();
        let id = r.create(NETLINK_ROUTE, 1, false).unwrap();
        let original = NlMsgHdr::new(NLMSG_MIN_TYPE, NLM_F_REQUEST, 42, 100, 0);
        let _ = r.send_ack(id, &original);
        let (hdr, _) = r.recv(id).unwrap();
        assert_eq!(hdr.nlmsg_type, NLMSG_ERROR);
        assert_eq!(hdr.nlmsg_seq, 42);
    }

    #[test]
    fn send_error() {
        let mut r = NetlinkRegistry::new();
        let id = r.create(NETLINK_ROUTE, 1, false).unwrap();
        let original = NlMsgHdr::new(NLMSG_MIN_TYPE, NLM_F_REQUEST, 10, 100, 0);
        let _ = r.send_error(id, &original, -22);
        let (hdr, _) = r.recv(id).unwrap();
        assert_eq!(hdr.nlmsg_type, NLMSG_ERROR);
    }

    #[test]
    fn dump_done() {
        let mut r = NetlinkRegistry::new();
        let id = r.create(NETLINK_ROUTE, 1, false).unwrap();
        let _ = r.send_dump_done(id, 5);
        let (hdr, _) = r.recv(id).unwrap();
        assert_eq!(hdr.nlmsg_type, NLMSG_DONE);
        assert!(hdr.is_multipart());
    }

    #[test]
    fn poll_socket() {
        let mut r = NetlinkRegistry::new();
        let id = r.create(NETLINK_ROUTE, 1, false).unwrap();
        assert_eq!(r.poll(id), Ok(0));
        let _ = r.send_to(id, NLMSG_NOOP, 0, &[], 0);
        assert_eq!(r.poll(id), Ok(0x01));
    }

    #[test]
    fn cleanup_pid() {
        let mut r = NetlinkRegistry::new();
        let _ = r.create(NETLINK_ROUTE, 42, false).unwrap();
        let _ = r.create(NETLINK_GENERIC, 42, false).unwrap();
        let _ = r.create(NETLINK_ROUTE, 99, false).unwrap();
        assert_eq!(r.count(), 3);
        r.cleanup_pid(42);
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn parse_nla_basic() {
        // Build a simple NLA: type=1, value=[0xAA, 0xBB]
        let buf = [
            6, 0, // nla_len = 6 (4 header + 2 value)
            1, 0, // nla_type = 1
            0xAA, 0xBB, // value
            0, 0, // padding to 4-byte alignment
        ];
        let result = parse_nla(&buf);
        assert!(result.is_some());
        let (attr, next) = result.unwrap();
        assert_eq!(attr.nla_type, 1);
        assert_eq!(attr.value_len(), 2);
        assert_eq!(next, 8); // aligned to 4 bytes
    }

    #[test]
    fn for_each_nla_multiple() {
        // Two NLAs back-to-back.
        let buf = [
            5, 0, 1, 0, 0xAA, 0, 0, 0, // NLA1: type=1, val=[0xAA], padded
            6, 0, 2, 0, 0xBB, 0xCC, 0, 0, // NLA2: type=2, val=[0xBB,0xCC], padded
        ];
        let mut types = [0u16; 2];
        let mut idx = 0;
        let count = for_each_nla(&buf, |attr, _val| {
            if idx < 2 {
                types[idx] = attr.nla_type;
                idx += 1;
            }
        });
        assert_eq!(count, 2);
        assert_eq!(types[0], 1);
        assert_eq!(types[1], 2);
    }

    #[test]
    fn err_msg_ack() {
        let h = NlMsgHdr::new(NLMSG_MIN_TYPE, 0, 1, 0, 0);
        let ack = NlErrMsg::ack(h);
        assert!(ack.is_ack());
    }

    #[test]
    fn err_msg_error() {
        let h = NlMsgHdr::new(NLMSG_MIN_TYPE, 0, 1, 0, 0);
        let err = NlErrMsg::error(-22, h);
        assert!(!err.is_ack());
        assert_eq!(err.error, -22);
    }

    #[test]
    fn socket_properties() {
        let mut r = NetlinkRegistry::new();
        let id = r.create(NETLINK_GENERIC, 100, true).unwrap();
        let sock = r.find(id).unwrap();
        assert_eq!(sock.family(), NETLINK_GENERIC);
        assert_eq!(sock.owner_pid(), 100);
        assert!(sock.is_active());
        assert!(sock.recv_queue_empty());
    }

    #[test]
    fn payload_too_large_rejected() {
        let mut r = NetlinkRegistry::new();
        let id = r.create(NETLINK_ROUTE, 1, false).unwrap();
        let big = [0u8; NLMSG_MAX_PAYLOAD + 1];
        assert_eq!(
            r.send_to(id, NLMSG_MIN_TYPE, 0, &big, 0),
            Err(Error::InvalidArgument)
        );
    }
}
