// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RPMSG — remote processor messaging framework.
//!
//! RPMSG provides a message-based IPC mechanism for communication
//! between the main processor and remote processors (DSPs, MCUs,
//! etc.) in heterogeneous multiprocessor systems. Messages are
//! routed by source and destination endpoint addresses.
//!
//! # Architecture
//!
//! ```text
//! Host Processor                 Remote Processor
//! ────────────────               ──────────────────
//! RpmsgEndpoint(src=10)  ──msg──►  RpmsgEndpoint(dst=10)
//! RpmsgEndpoint(src=20)  ◄──msg──  RpmsgEndpoint(dst=20)
//!              │                          │
//!              └──── virtio transport ────┘
//! ```
//!
//! # Concepts
//!
//! - **Device**: Represents a remote processor with a transport channel.
//! - **Endpoint**: A logical port identified by a 32-bit address.
//! - **Channel**: A named bidirectional link between two endpoints.
//! - **Name Service**: Announces new services to the remote side.
//!
//! # Message format
//!
//! Each message has a 16-byte header ([`RpmsgHeader`]) followed by
//! up to [`RPMSG_MAX_PAYLOAD`] bytes of data.
//!
//! # References
//!
//! - Linux: `drivers/rpmsg/`, `include/linux/rpmsg.h`
//! - Virtio specification: virtio-rpmsg transport

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum payload size per message (512 bytes, matching virtio-rpmsg).
pub const RPMSG_MAX_PAYLOAD: usize = 512;

/// Maximum length of a channel name.
pub const RPMSG_NAME_SIZE: usize = 32;

/// Maximum number of endpoints per device.
const MAX_ENDPOINTS: usize = 64;

/// Maximum number of RPMSG devices.
const MAX_DEVICES: usize = 8;

/// Maximum pending messages per endpoint.
const MAX_PENDING_MSGS: usize = 32;

/// Address indicating "any" (for dynamic allocation).
pub const RPMSG_ADDR_ANY: u32 = 0xFFFF_FFFF;

/// Name service announcement address (well-known).
pub const RPMSG_NS_ADDR: u32 = 53;

/// First dynamically allocated endpoint address.
const RPMSG_DYNAMIC_ADDR_START: u32 = 1024;

// ---------------------------------------------------------------------------
// Name service announcement types
// ---------------------------------------------------------------------------

/// Name service: create a new channel.
pub const RPMSG_NS_CREATE: u32 = 0;
/// Name service: destroy an existing channel.
pub const RPMSG_NS_DESTROY: u32 = 1;

// ---------------------------------------------------------------------------
// RpmsgHeader — message header
// ---------------------------------------------------------------------------

/// RPMSG message header (16 bytes).
///
/// Precedes every message transmitted over the transport.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RpmsgHeader {
    /// Source endpoint address.
    pub src: u32,
    /// Destination endpoint address.
    pub dst: u32,
    /// Reserved (must be 0).
    pub reserved: u32,
    /// Payload length in bytes.
    pub len: u16,
    /// Flags (reserved, must be 0).
    pub flags: u16,
}

impl RpmsgHeader {
    /// Create a new message header.
    pub const fn new(src: u32, dst: u32, len: u16) -> Self {
        Self {
            src,
            dst,
            reserved: 0,
            len,
            flags: 0,
        }
    }

    /// Validate the header.
    pub fn validate(&self) -> Result<()> {
        if self.len as usize > RPMSG_MAX_PAYLOAD {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RpmsgMessage — a complete message
// ---------------------------------------------------------------------------

/// A complete RPMSG message (header + payload).
#[derive(Clone)]
pub struct RpmsgMessage {
    /// Message header.
    pub header: RpmsgHeader,
    /// Payload data.
    pub data: [u8; RPMSG_MAX_PAYLOAD],
    /// Actual data length.
    pub data_len: usize,
}

impl RpmsgMessage {
    /// Create a new message.
    pub fn new(src: u32, dst: u32, payload: &[u8]) -> Result<Self> {
        if payload.len() > RPMSG_MAX_PAYLOAD {
            return Err(Error::InvalidArgument);
        }
        let header = RpmsgHeader::new(src, dst, payload.len() as u16);
        let mut data = [0u8; RPMSG_MAX_PAYLOAD];
        data[..payload.len()].copy_from_slice(payload);
        Ok(Self {
            header,
            data,
            data_len: payload.len(),
        })
    }

    /// Return a slice of the payload data.
    pub fn payload(&self) -> &[u8] {
        &self.data[..self.data_len]
    }
}

// ---------------------------------------------------------------------------
// ChannelName — fixed-size channel name
// ---------------------------------------------------------------------------

/// A fixed-size RPMSG channel name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelName {
    /// Name bytes (NUL-terminated).
    bytes: [u8; RPMSG_NAME_SIZE],
    /// Actual length (excluding NUL).
    len: usize,
}

impl ChannelName {
    /// Create a channel name from a byte slice.
    pub fn from_bytes(name: &[u8]) -> Result<Self> {
        if name.is_empty() || name.len() >= RPMSG_NAME_SIZE {
            return Err(Error::InvalidArgument);
        }
        let mut bytes = [0u8; RPMSG_NAME_SIZE];
        bytes[..name.len()].copy_from_slice(name);
        Ok(Self {
            bytes,
            len: name.len(),
        })
    }

    /// Return the name as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Return the raw fixed-size buffer.
    pub const fn raw(&self) -> &[u8; RPMSG_NAME_SIZE] {
        &self.bytes
    }
}

// ---------------------------------------------------------------------------
// RpmsgEndpoint — a communication endpoint
// ---------------------------------------------------------------------------

/// An RPMSG endpoint.
///
/// Endpoints are identified by a 32-bit address and can send/receive
/// messages to/from other endpoints.
pub struct RpmsgEndpoint {
    /// Endpoint address.
    pub addr: u32,
    /// Channel name (for named endpoints).
    pub name: Option<ChannelName>,
    /// Whether this endpoint is active.
    pub active: bool,
    /// Receive queue (ring buffer of messages).
    rx_queue: [Option<RpmsgMessage>; MAX_PENDING_MSGS],
    /// Receive queue head (next read).
    rx_head: usize,
    /// Receive queue tail (next write).
    rx_tail: usize,
    /// Number of queued messages.
    rx_count: usize,
}

impl RpmsgEndpoint {
    /// Create a new endpoint.
    pub fn new(addr: u32, name: Option<ChannelName>) -> Self {
        Self {
            addr,
            name,
            active: true,
            rx_queue: [const { None }; MAX_PENDING_MSGS],
            rx_head: 0,
            rx_tail: 0,
            rx_count: 0,
        }
    }

    /// Enqueue a received message.
    pub fn enqueue(&mut self, msg: RpmsgMessage) -> Result<()> {
        if self.rx_count >= MAX_PENDING_MSGS {
            return Err(Error::WouldBlock);
        }
        self.rx_queue[self.rx_tail] = Some(msg);
        self.rx_tail = (self.rx_tail + 1) % MAX_PENDING_MSGS;
        self.rx_count += 1;
        Ok(())
    }

    /// Dequeue a message (blocking semantics: returns WouldBlock if empty).
    pub fn dequeue(&mut self) -> Result<RpmsgMessage> {
        if self.rx_count == 0 {
            return Err(Error::WouldBlock);
        }
        let msg = self.rx_queue[self.rx_head].take().ok_or(Error::IoError)?;
        self.rx_head = (self.rx_head + 1) % MAX_PENDING_MSGS;
        self.rx_count -= 1;
        Ok(msg)
    }

    /// Try to receive a message (non-blocking).
    pub fn try_recv(&mut self) -> Option<RpmsgMessage> {
        if self.rx_count == 0 {
            return None;
        }
        let msg = self.rx_queue[self.rx_head].take();
        if msg.is_some() {
            self.rx_head = (self.rx_head + 1) % MAX_PENDING_MSGS;
            self.rx_count -= 1;
        }
        msg
    }

    /// Return the number of pending messages.
    pub const fn pending_count(&self) -> usize {
        self.rx_count
    }
}

// ---------------------------------------------------------------------------
// NameServiceAnnouncement — NS message
// ---------------------------------------------------------------------------

/// A name service announcement.
#[derive(Debug, Clone, Copy)]
pub struct NameServiceAnnouncement {
    /// Channel name.
    pub name: [u8; RPMSG_NAME_SIZE],
    /// Endpoint address.
    pub addr: u32,
    /// Announcement type (create or destroy).
    pub flags: u32,
}

impl NameServiceAnnouncement {
    /// Create a new NS announcement.
    pub fn new(name: &ChannelName, addr: u32, flags: u32) -> Self {
        Self {
            name: *name.raw(),
            addr,
            flags,
        }
    }
}

// ---------------------------------------------------------------------------
// RpmsgDevice — a remote processor device
// ---------------------------------------------------------------------------

/// An RPMSG device representing a remote processor.
///
/// Manages endpoints and message routing for one transport channel.
pub struct RpmsgDevice {
    /// Device index.
    pub index: usize,
    /// Whether the device is online.
    pub online: bool,
    /// Endpoints owned by this device.
    endpoints: [Option<RpmsgEndpoint>; MAX_ENDPOINTS],
    /// Number of active endpoints.
    endpoint_count: usize,
    /// Next dynamic address to allocate.
    next_addr: u32,
    /// Name service announcement log.
    ns_log: [Option<NameServiceAnnouncement>; MAX_ENDPOINTS],
    /// Number of NS announcements.
    ns_count: usize,
}

impl RpmsgDevice {
    /// Create a new RPMSG device.
    pub fn new(index: usize) -> Self {
        Self {
            index,
            online: true,
            endpoints: [const { None }; MAX_ENDPOINTS],
            endpoint_count: 0,
            next_addr: RPMSG_DYNAMIC_ADDR_START,
            ns_log: [const { None }; MAX_ENDPOINTS],
            ns_count: 0,
        }
    }

    /// Allocate a dynamic endpoint address.
    fn alloc_addr(&mut self) -> u32 {
        let addr = self.next_addr;
        self.next_addr = self.next_addr.wrapping_add(1);
        addr
    }

    /// Find a free endpoint slot.
    fn find_free_slot(&self) -> Result<usize> {
        for (i, slot) in self.endpoints.iter().enumerate() {
            if slot.is_none() {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find an endpoint by address.
    fn find_endpoint(&self, addr: u32) -> Result<usize> {
        for (i, slot) in self.endpoints.iter().enumerate() {
            if let Some(ep) = slot {
                if ep.addr == addr && ep.active {
                    return Ok(i);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Find an endpoint by channel name.
    fn find_endpoint_by_name(&self, name: &ChannelName) -> Option<usize> {
        for (i, slot) in self.endpoints.iter().enumerate() {
            if let Some(ep) = slot {
                if let Some(ep_name) = &ep.name {
                    if ep_name == name && ep.active {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    /// Create a new endpoint.
    ///
    /// If `addr` is `RPMSG_ADDR_ANY`, a dynamic address is allocated.
    pub fn create_endpoint(&mut self, addr: u32, name: Option<ChannelName>) -> Result<u32> {
        let slot = self.find_free_slot()?;

        // Check for name collision.
        if let Some(n) = name {
            if self.find_endpoint_by_name(&n).is_some() {
                return Err(Error::AlreadyExists);
            }
        }

        let actual_addr = if addr == RPMSG_ADDR_ANY {
            self.alloc_addr()
        } else {
            // Check for address collision.
            if self.find_endpoint(addr).is_ok() {
                return Err(Error::AlreadyExists);
            }
            addr
        };

        // Record NS announcement for named endpoints.
        if let Some(n) = name {
            self.log_ns_announcement(&n, actual_addr, RPMSG_NS_CREATE);
        }

        self.endpoints[slot] = Some(RpmsgEndpoint::new(actual_addr, name));
        self.endpoint_count += 1;
        Ok(actual_addr)
    }

    /// Destroy an endpoint by address.
    pub fn destroy_endpoint(&mut self, addr: u32) -> Result<()> {
        let slot = self.find_endpoint(addr)?;
        let ep_name = self.endpoints[slot].as_ref().and_then(|ep| ep.name);
        if let Some(n) = ep_name {
            self.log_ns_announcement(&n, addr, RPMSG_NS_DESTROY);
        }
        self.endpoints[slot] = None;
        self.endpoint_count = self.endpoint_count.saturating_sub(1);
        Ok(())
    }

    /// Send a message from src to dst endpoint.
    pub fn send(&mut self, src: u32, dst: u32, payload: &[u8]) -> Result<()> {
        if !self.online {
            return Err(Error::IoError);
        }
        // Verify src exists.
        let _ = self.find_endpoint(src)?;
        // Route to dst.
        let dst_slot = self.find_endpoint(dst)?;
        let msg = RpmsgMessage::new(src, dst, payload)?;
        match &mut self.endpoints[dst_slot] {
            Some(ep) => ep.enqueue(msg),
            None => Err(Error::NotFound),
        }
    }

    /// Try to send (non-blocking, returns WouldBlock if dst queue is full).
    pub fn trysend(&mut self, src: u32, dst: u32, payload: &[u8]) -> Result<()> {
        self.send(src, dst, payload)
    }

    /// Receive a message from an endpoint's queue.
    pub fn recv(&mut self, addr: u32) -> Result<RpmsgMessage> {
        let slot = self.find_endpoint(addr)?;
        match &mut self.endpoints[slot] {
            Some(ep) => ep.dequeue(),
            None => Err(Error::NotFound),
        }
    }

    /// Return the number of active endpoints.
    pub const fn endpoint_count(&self) -> usize {
        self.endpoint_count
    }

    /// Log a name service announcement.
    fn log_ns_announcement(&mut self, name: &ChannelName, addr: u32, flags: u32) {
        if self.ns_count < MAX_ENDPOINTS {
            let ann = NameServiceAnnouncement::new(name, addr, flags);
            self.ns_log[self.ns_count] = Some(ann);
            self.ns_count += 1;
        }
    }

    /// Return the number of NS announcements.
    pub const fn ns_announcement_count(&self) -> usize {
        self.ns_count
    }
}

// ---------------------------------------------------------------------------
// RpmsgBus — global RPMSG bus
// ---------------------------------------------------------------------------

/// Global RPMSG bus managing all devices.
pub struct RpmsgBus {
    /// Registered devices.
    devices: [Option<RpmsgDevice>; MAX_DEVICES],
    /// Number of registered devices.
    device_count: usize,
}

impl RpmsgBus {
    /// Create a new empty RPMSG bus.
    pub fn new() -> Self {
        Self {
            devices: [const { None }; MAX_DEVICES],
            device_count: 0,
        }
    }

    /// Register a new device.
    pub fn register_device(&mut self) -> Result<usize> {
        for (i, slot) in self.devices.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(RpmsgDevice::new(i));
                self.device_count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Get a mutable reference to a device.
    pub fn get_device_mut(&mut self, index: usize) -> Result<&mut RpmsgDevice> {
        if index >= MAX_DEVICES {
            return Err(Error::InvalidArgument);
        }
        self.devices[index].as_mut().ok_or(Error::NotFound)
    }

    /// Get a reference to a device.
    pub fn get_device(&self, index: usize) -> Result<&RpmsgDevice> {
        if index >= MAX_DEVICES {
            return Err(Error::InvalidArgument);
        }
        self.devices[index].as_ref().ok_or(Error::NotFound)
    }

    /// Remove a device.
    pub fn unregister_device(&mut self, index: usize) -> Result<()> {
        if index >= MAX_DEVICES {
            return Err(Error::InvalidArgument);
        }
        if self.devices[index].is_none() {
            return Err(Error::NotFound);
        }
        self.devices[index] = None;
        self.device_count = self.device_count.saturating_sub(1);
        Ok(())
    }

    /// Return the number of registered devices.
    pub const fn device_count(&self) -> usize {
        self.device_count
    }
}

impl Default for RpmsgBus {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_name() -> ChannelName {
        ChannelName::from_bytes(b"test-channel").unwrap()
    }

    #[test]
    fn test_channel_name() {
        let name = ChannelName::from_bytes(b"hello").unwrap();
        assert_eq!(name.as_bytes(), b"hello");
    }

    #[test]
    fn test_channel_name_empty() {
        assert_eq!(
            ChannelName::from_bytes(b"").unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_channel_name_too_long() {
        let long = [b'a'; RPMSG_NAME_SIZE];
        assert_eq!(
            ChannelName::from_bytes(&long).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_message_create() {
        let msg = RpmsgMessage::new(10, 20, b"hello").unwrap();
        assert_eq!(msg.header.src, 10);
        assert_eq!(msg.header.dst, 20);
        assert_eq!(msg.payload(), b"hello");
    }

    #[test]
    fn test_message_too_large() {
        let big = [0u8; RPMSG_MAX_PAYLOAD + 1];
        assert_eq!(
            RpmsgMessage::new(0, 0, &big).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_create_endpoint_dynamic() {
        let mut dev = RpmsgDevice::new(0);
        let addr = dev.create_endpoint(RPMSG_ADDR_ANY, None).unwrap();
        assert!(addr >= RPMSG_DYNAMIC_ADDR_START);
        assert_eq!(dev.endpoint_count(), 1);
    }

    #[test]
    fn test_create_endpoint_fixed() {
        let mut dev = RpmsgDevice::new(0);
        let addr = dev.create_endpoint(42, None).unwrap();
        assert_eq!(addr, 42);
    }

    #[test]
    fn test_create_endpoint_named() {
        let mut dev = RpmsgDevice::new(0);
        let name = test_name();
        let addr = dev.create_endpoint(RPMSG_ADDR_ANY, Some(name)).unwrap();
        assert!(addr > 0);
        assert_eq!(dev.ns_announcement_count(), 1);
    }

    #[test]
    fn test_create_endpoint_duplicate_name() {
        let mut dev = RpmsgDevice::new(0);
        let name = test_name();
        dev.create_endpoint(RPMSG_ADDR_ANY, Some(name)).unwrap();
        assert_eq!(
            dev.create_endpoint(RPMSG_ADDR_ANY, Some(name)).unwrap_err(),
            Error::AlreadyExists
        );
    }

    #[test]
    fn test_create_endpoint_duplicate_addr() {
        let mut dev = RpmsgDevice::new(0);
        dev.create_endpoint(42, None).unwrap();
        assert_eq!(
            dev.create_endpoint(42, None).unwrap_err(),
            Error::AlreadyExists
        );
    }

    #[test]
    fn test_destroy_endpoint() {
        let mut dev = RpmsgDevice::new(0);
        let addr = dev.create_endpoint(50, None).unwrap();
        assert!(dev.destroy_endpoint(addr).is_ok());
        assert_eq!(dev.endpoint_count(), 0);
    }

    #[test]
    fn test_destroy_nonexistent() {
        let mut dev = RpmsgDevice::new(0);
        assert_eq!(dev.destroy_endpoint(999).unwrap_err(), Error::NotFound);
    }

    #[test]
    fn test_send_recv() {
        let mut dev = RpmsgDevice::new(0);
        let src = dev.create_endpoint(10, None).unwrap();
        let dst = dev.create_endpoint(20, None).unwrap();

        dev.send(src, dst, b"hello rpmsg").unwrap();
        let msg = dev.recv(dst).unwrap();
        assert_eq!(msg.header.src, 10);
        assert_eq!(msg.payload(), b"hello rpmsg");
    }

    #[test]
    fn test_recv_empty() {
        let mut dev = RpmsgDevice::new(0);
        let addr = dev.create_endpoint(10, None).unwrap();
        assert_eq!(dev.recv(addr).unwrap_err(), Error::WouldBlock);
    }

    #[test]
    fn test_send_offline_device() {
        let mut dev = RpmsgDevice::new(0);
        dev.online = false;
        let src = 10;
        // Cannot create endpoints on offline device easily, so test send.
        assert_eq!(dev.send(src, 20, b"data").unwrap_err(), Error::NotFound);
    }

    #[test]
    fn test_trysend() {
        let mut dev = RpmsgDevice::new(0);
        let src = dev.create_endpoint(10, None).unwrap();
        let dst = dev.create_endpoint(20, None).unwrap();
        assert!(dev.trysend(src, dst, b"data").is_ok());
    }

    #[test]
    fn test_endpoint_try_recv() {
        let mut ep = RpmsgEndpoint::new(10, None);
        assert!(ep.try_recv().is_none());
        let msg = RpmsgMessage::new(20, 10, b"data").unwrap();
        ep.enqueue(msg).unwrap();
        let got = ep.try_recv().unwrap();
        assert_eq!(got.payload(), b"data");
    }

    #[test]
    fn test_rpmsg_bus() {
        let mut bus = RpmsgBus::new();
        let idx = bus.register_device().unwrap();
        assert_eq!(bus.device_count(), 1);
        {
            let dev = bus.get_device_mut(idx).unwrap();
            dev.create_endpoint(10, None).unwrap();
        }
        assert!(bus.unregister_device(idx).is_ok());
        assert_eq!(bus.device_count(), 0);
    }

    #[test]
    fn test_bus_unregister_nonexistent() {
        let mut bus = RpmsgBus::new();
        assert_eq!(bus.unregister_device(0).unwrap_err(), Error::NotFound);
    }

    #[test]
    fn test_header_validate() {
        let h = RpmsgHeader::new(0, 0, RPMSG_MAX_PAYLOAD as u16);
        assert!(h.validate().is_ok());
        let h2 = RpmsgHeader::new(0, 0, RPMSG_MAX_PAYLOAD as u16 + 1);
        assert_eq!(h2.validate().unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn test_ns_announcement() {
        let name = test_name();
        let ann = NameServiceAnnouncement::new(&name, 42, RPMSG_NS_CREATE);
        assert_eq!(ann.addr, 42);
        assert_eq!(ann.flags, RPMSG_NS_CREATE);
    }

    #[test]
    fn test_named_endpoint_destroy_ns() {
        let mut dev = RpmsgDevice::new(0);
        let name = test_name();
        let addr = dev.create_endpoint(RPMSG_ADDR_ANY, Some(name)).unwrap();
        assert_eq!(dev.ns_announcement_count(), 1); // create
        dev.destroy_endpoint(addr).unwrap();
        assert_eq!(dev.ns_announcement_count(), 2); // create + destroy
    }
}
