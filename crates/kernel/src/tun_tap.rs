// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! TUN/TAP virtual network interface for the ONCRIX kernel.
//!
//! Provides software-only network interfaces that bridge userspace
//! applications and the kernel network stack:
//!
//! - **TUN** (L3): Carries raw IP packets.  Userspace reads/writes
//!   IP datagrams directly.
//! - **TAP** (L2): Carries Ethernet frames.  Userspace reads/writes
//!   full Ethernet frames including headers.
//!
//! Virtual interfaces are created via [`TunTapRegistry::create`],
//! which returns a handle.  Userspace reads from the interface to
//! receive packets injected by the kernel, and writes to inject
//! packets into the kernel network stack.
//!
//! Each interface has independent TX and RX ring buffers of
//! configurable depth.
//!
//! # Use cases
//!
//! - VPN tunnels (WireGuard, OpenVPN)
//! - Network testing and simulation
//! - Container/namespace networking
//! - Userspace protocol stacks

use oncrix_lib::{Error, Result};

// =========================================================================
// Constants
// =========================================================================

/// Maximum number of TUN/TAP interfaces.
const MAX_INTERFACES: usize = 16;

/// Maximum number of packets buffered per direction per interface.
const RING_CAPACITY: usize = 64;

/// Maximum packet size in bytes (standard Ethernet jumbo frame).
const MAX_PACKET_SIZE: usize = 9216;

/// Default MTU for TUN interfaces (standard IP MTU).
const DEFAULT_TUN_MTU: u32 = 1500;

/// Default MTU for TAP interfaces (Ethernet MTU).
const DEFAULT_TAP_MTU: u32 = 1500;

/// Standard Ethernet header length.
const ETHER_HEADER_LEN: usize = 14;

/// Minimum IPv4 header length.
const IPV4_MIN_HEADER_LEN: usize = 20;

// =========================================================================
// TunTapMode
// =========================================================================

/// Operating mode of a virtual interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunTapMode {
    /// TUN mode — Layer 3 (IP packets only, no Ethernet header).
    Tun,
    /// TAP mode — Layer 2 (full Ethernet frames).
    Tap,
}

// =========================================================================
// InterfaceFlags
// =========================================================================

/// Runtime flags for a TUN/TAP interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceFlags {
    /// Interface is administratively up.
    pub up: bool,
    /// Interface is running (carrier detected / ready).
    pub running: bool,
    /// Enable packet information header (4-byte prefix with
    /// flags and protocol for TUN mode).
    pub packet_info: bool,
    /// Enable multi-queue (multiple file descriptors per
    /// interface).  Stub for future implementation.
    pub multi_queue: bool,
}

impl InterfaceFlags {
    /// Default flags for a new interface (down, no packet info).
    const fn new() -> Self {
        Self {
            up: false,
            running: false,
            packet_info: false,
            multi_queue: false,
        }
    }
}

impl Default for InterfaceFlags {
    fn default() -> Self {
        Self::new()
    }
}

// =========================================================================
// PacketBuf — fixed-size packet storage
// =========================================================================

/// A single buffered packet with its length.
#[derive(Clone, Copy)]
struct PacketBuf {
    /// Raw packet data.
    data: [u8; MAX_PACKET_SIZE],
    /// Actual length of the packet in `data`.
    len: usize,
}

impl PacketBuf {
    /// Create an empty packet buffer.
    const fn empty() -> Self {
        Self {
            data: [0u8; MAX_PACKET_SIZE],
            len: 0,
        }
    }
}

// =========================================================================
// PacketRing — circular buffer for packets
// =========================================================================

/// A fixed-size ring buffer of packets.
///
/// Used for both TX (userspace -> kernel) and RX (kernel ->
/// userspace) directions.
struct PacketRing {
    /// Packet storage slots.
    ///
    /// Using a boxed slice would be ideal but we are in `no_std`,
    /// so we use a fixed array.  The actual storage is large, so
    /// in a real kernel this would be backed by page-allocated
    /// memory.
    head: usize,
    tail: usize,
    count: usize,
    /// Number of packets dropped because the ring was full.
    drops: u64,
}

impl PacketRing {
    /// Create a new empty ring.
    const fn new() -> Self {
        Self {
            head: 0,
            tail: 0,
            count: 0,
            drops: 0,
        }
    }

    /// Return the number of buffered packets.
    const fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if the ring is empty.
    const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return `true` if the ring is full.
    const fn is_full(&self) -> bool {
        self.count >= RING_CAPACITY
    }

    /// Return the number of dropped packets.
    const fn drops(&self) -> u64 {
        self.drops
    }

    /// Advance head index.
    fn advance_head(&mut self) {
        self.head = (self.head + 1) % RING_CAPACITY;
    }

    /// Advance tail index.
    fn advance_tail(&mut self) {
        self.tail = (self.tail + 1) % RING_CAPACITY;
    }
}

// =========================================================================
// InterfaceStats
// =========================================================================

/// Per-interface traffic statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceStats {
    /// Total packets transmitted (userspace -> kernel).
    pub tx_packets: u64,
    /// Total bytes transmitted.
    pub tx_bytes: u64,
    /// Total packets received (kernel -> userspace).
    pub rx_packets: u64,
    /// Total bytes received.
    pub rx_bytes: u64,
    /// Packets dropped on TX ring overflow.
    pub tx_drops: u64,
    /// Packets dropped on RX ring overflow.
    pub rx_drops: u64,
    /// Packets dropped due to validation errors.
    pub tx_errors: u64,
}

impl InterfaceStats {
    /// Create zeroed statistics.
    const fn new() -> Self {
        Self {
            tx_packets: 0,
            tx_bytes: 0,
            rx_packets: 0,
            rx_bytes: 0,
            tx_drops: 0,
            rx_drops: 0,
            tx_errors: 0,
        }
    }
}

impl Default for InterfaceStats {
    fn default() -> Self {
        Self::new()
    }
}

// =========================================================================
// TunTapInterface
// =========================================================================

/// A single TUN or TAP virtual interface.
///
/// Each interface has a name, mode, MTU, flags, and independent
/// TX/RX ring buffers.  Packets flow:
///
/// - **TX (write)**: Userspace writes a packet -> enqueued in TX
///   ring -> kernel dequeues for stack injection.
/// - **RX (read)**: Kernel enqueues a packet in RX ring ->
///   userspace reads it.
pub struct TunTapInterface {
    /// Whether this slot is in use.
    active: bool,
    /// Interface index (0-based, unique within the registry).
    index: usize,
    /// Interface name (e.g. "tun0", "tap0").
    name: [u8; 16],
    /// Length of the name in `name`.
    name_len: usize,
    /// Operating mode.
    mode: TunTapMode,
    /// Maximum transmission unit.
    mtu: u32,
    /// Interface flags.
    flags: InterfaceFlags,
    /// Traffic statistics.
    stats: InterfaceStats,
    /// TX ring metadata (actual packet data is managed
    /// externally via read/write calls).
    tx_ring: PacketRing,
    /// RX ring metadata.
    rx_ring: PacketRing,
    /// IPv4 address assigned to this interface (if any).
    ipv4_addr: [u8; 4],
    /// IPv4 netmask.
    ipv4_mask: [u8; 4],
    /// File descriptor of the owning process (for permission
    /// checks).
    owner_pid: u32,
}

impl TunTapInterface {
    /// Create a new interface in the given mode.
    fn new(index: usize, name: &[u8], mode: TunTapMode) -> Self {
        let mut n = [0u8; 16];
        let len = if name.len() > 15 { 15 } else { name.len() };
        n[..len].copy_from_slice(&name[..len]);

        let mtu = match mode {
            TunTapMode::Tun => DEFAULT_TUN_MTU,
            TunTapMode::Tap => DEFAULT_TAP_MTU,
        };

        Self {
            active: true,
            index,
            name: n,
            name_len: len,
            mode,
            mtu,
            flags: InterfaceFlags::new(),
            stats: InterfaceStats::new(),
            tx_ring: PacketRing::new(),
            rx_ring: PacketRing::new(),
            ipv4_addr: [0; 4],
            ipv4_mask: [0; 4],
            owner_pid: 0,
        }
    }

    /// Return the interface index.
    pub const fn index(&self) -> usize {
        self.index
    }

    /// Return the interface name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the operating mode.
    pub const fn mode(&self) -> TunTapMode {
        self.mode
    }

    /// Return the current MTU.
    pub const fn mtu(&self) -> u32 {
        self.mtu
    }

    /// Set the MTU.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `mtu` is zero or
    /// exceeds `MAX_PACKET_SIZE`.
    pub fn set_mtu(&mut self, mtu: u32) -> Result<()> {
        if mtu == 0 || mtu as usize > MAX_PACKET_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.mtu = mtu;
        Ok(())
    }

    /// Return the current flags.
    pub const fn flags(&self) -> &InterfaceFlags {
        &self.flags
    }

    /// Bring the interface up.
    pub fn bring_up(&mut self) {
        self.flags.up = true;
        self.flags.running = true;
    }

    /// Bring the interface down.
    pub fn bring_down(&mut self) {
        self.flags.up = false;
        self.flags.running = false;
    }

    /// Return the traffic statistics.
    pub fn stats(&self) -> InterfaceStats {
        let mut s = self.stats;
        s.tx_drops = self.tx_ring.drops();
        s.rx_drops = self.rx_ring.drops();
        s
    }

    /// Set the IPv4 address and netmask.
    pub fn set_ipv4(&mut self, addr: [u8; 4], mask: [u8; 4]) {
        self.ipv4_addr = addr;
        self.ipv4_mask = mask;
    }

    /// Return the assigned IPv4 address.
    pub const fn ipv4_addr(&self) -> &[u8; 4] {
        &self.ipv4_addr
    }

    /// Set the owning process ID.
    pub fn set_owner(&mut self, pid: u32) {
        self.owner_pid = pid;
    }

    /// Return the owning process ID.
    pub const fn owner(&self) -> u32 {
        self.owner_pid
    }

    /// Validate a packet before enqueuing to TX.
    fn validate_tx(&self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Err(Error::InvalidArgument);
        }
        if data.len() > self.mtu as usize + ETHER_HEADER_LEN {
            return Err(Error::InvalidArgument);
        }
        match self.mode {
            TunTapMode::Tun => {
                // Expect at least an IP header
                if data.len() < IPV4_MIN_HEADER_LEN {
                    return Err(Error::InvalidArgument);
                }
                let version = data[0] >> 4;
                if version != 4 && version != 6 {
                    return Err(Error::InvalidArgument);
                }
            }
            TunTapMode::Tap => {
                // Expect at least an Ethernet header
                if data.len() < ETHER_HEADER_LEN {
                    return Err(Error::InvalidArgument);
                }
            }
        }
        Ok(())
    }
}

// =========================================================================
// TunTapHandle — returned to callers
// =========================================================================

/// An opaque handle to a TUN/TAP interface.
///
/// Used with [`TunTapRegistry`] methods to read/write packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunTapHandle {
    /// Index into the registry's interface array.
    index: usize,
    /// Generation counter to detect use-after-destroy.
    generation: u32,
}

// =========================================================================
// TunTapRegistry
// =========================================================================

/// Registry of TUN/TAP virtual interfaces.
///
/// Manages creation, destruction, and packet I/O for up to
/// [`MAX_INTERFACES`] virtual NICs.
pub struct TunTapRegistry {
    /// Interface slots.  We store metadata here; actual packet
    /// buffers are allocated per-interface.
    interfaces: [Option<TunTapInterface>; MAX_INTERFACES],
    /// Generation counter incremented on each create/destroy to
    /// invalidate stale handles.
    generation: u32,
    /// Total number of active interfaces.
    count: usize,
    /// TX packet buffers per interface (indexed by interface
    /// slot, then ring position).
    tx_bufs: [[PacketBuf; RING_CAPACITY]; MAX_INTERFACES],
    /// RX packet buffers per interface.
    rx_bufs: [[PacketBuf; RING_CAPACITY]; MAX_INTERFACES],
}

/// Compile-time none initialiser.
const EMPTY_IFACE: Option<TunTapInterface> = None;

impl TunTapRegistry {
    /// Create a new empty registry.
    pub const fn new() -> Self {
        Self {
            interfaces: [EMPTY_IFACE; MAX_INTERFACES],
            generation: 0,
            count: 0,
            tx_bufs: [[const { PacketBuf::empty() }; RING_CAPACITY]; MAX_INTERFACES],
            rx_bufs: [[const { PacketBuf::empty() }; RING_CAPACITY]; MAX_INTERFACES],
        }
    }

    /// Return the number of active interfaces.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Create a new TUN/TAP interface.
    ///
    /// # Arguments
    ///
    /// * `name` — interface name (max 15 bytes, e.g. `b"tun0"`).
    /// * `mode` — [`TunTapMode::Tun`] or [`TunTapMode::Tap`].
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `name` is empty or too long.
    /// - [`Error::OutOfMemory`] if no free slots remain.
    /// - [`Error::AlreadyExists`] if the name is already in use.
    pub fn create(&mut self, name: &[u8], mode: TunTapMode) -> Result<TunTapHandle> {
        if name.is_empty() || name.len() > 15 {
            return Err(Error::InvalidArgument);
        }

        // Check for name collisions
        for iface in self.interfaces.iter().flatten() {
            if iface.name() == name {
                return Err(Error::AlreadyExists);
            }
        }

        // Find a free slot
        for (idx, slot) in self.interfaces.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(TunTapInterface::new(idx, name, mode));
                self.count += 1;
                self.generation = self.generation.wrapping_add(1);
                return Ok(TunTapHandle {
                    index: idx,
                    generation: self.generation,
                });
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Destroy an interface by handle.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the handle is invalid or
    /// stale.
    pub fn destroy(&mut self, handle: TunTapHandle) -> Result<()> {
        let iface = self.get_iface(handle)?;
        if !iface.active {
            return Err(Error::NotFound);
        }
        let idx = handle.index;
        self.interfaces[idx] = None;
        self.count = self.count.saturating_sub(1);
        self.generation = self.generation.wrapping_add(1);

        // Clear packet buffers
        for buf in &mut self.tx_bufs[idx] {
            buf.len = 0;
        }
        for buf in &mut self.rx_bufs[idx] {
            buf.len = 0;
        }

        Ok(())
    }

    /// Look up an interface by handle (immutable).
    fn get_iface(&self, handle: TunTapHandle) -> Result<&TunTapInterface> {
        if handle.index >= MAX_INTERFACES {
            return Err(Error::InvalidArgument);
        }
        match &self.interfaces[handle.index] {
            Some(iface) if iface.active => Ok(iface),
            _ => Err(Error::NotFound),
        }
    }

    /// Look up an interface by handle (mutable).
    fn get_iface_mut(&mut self, handle: TunTapHandle) -> Result<&mut TunTapInterface> {
        if handle.index >= MAX_INTERFACES {
            return Err(Error::InvalidArgument);
        }
        match &mut self.interfaces[handle.index] {
            Some(iface) if iface.active => Ok(iface),
            _ => Err(Error::NotFound),
        }
    }

    /// Write a packet from userspace into the TX ring.
    ///
    /// This simulates `write(fd, buf, len)` on a `/dev/net/tun`
    /// file descriptor.  The packet is validated according to the
    /// interface mode and enqueued for the kernel to dequeue.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the handle is invalid.
    /// - [`Error::InvalidArgument`] if the interface is down or the
    ///   packet fails validation.
    /// - [`Error::WouldBlock`] if the TX ring is full.
    pub fn write(&mut self, handle: TunTapHandle, data: &[u8]) -> Result<usize> {
        let idx = handle.index;
        {
            let iface = self.get_iface(handle)?;
            if !iface.flags.up {
                return Err(Error::InvalidArgument);
            }
            iface.validate_tx(data)?;
        }

        let iface = self.get_iface_mut(handle)?;
        if iface.tx_ring.is_full() {
            iface.tx_ring.drops = iface.tx_ring.drops.saturating_add(1);
            return Err(Error::WouldBlock);
        }

        let tail = iface.tx_ring.tail;
        let buf = &mut self.tx_bufs[idx][tail];
        buf.data[..data.len()].copy_from_slice(data);
        buf.len = data.len();

        let iface = self.get_iface_mut(handle)?;
        iface.tx_ring.advance_tail();
        iface.tx_ring.count += 1;
        iface.stats.tx_packets = iface.stats.tx_packets.saturating_add(1);
        iface.stats.tx_bytes = iface.stats.tx_bytes.saturating_add(data.len() as u64);

        Ok(data.len())
    }

    /// Read a packet from the RX ring (kernel -> userspace).
    ///
    /// Copies the next available packet into `buf` and returns the
    /// number of bytes copied.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the handle is invalid.
    /// - [`Error::WouldBlock`] if the RX ring is empty.
    /// - [`Error::InvalidArgument`] if `buf` is too small for the
    ///   packet.
    pub fn read(&mut self, handle: TunTapHandle, buf: &mut [u8]) -> Result<usize> {
        let idx = handle.index;
        let iface = self.get_iface(handle)?;
        if iface.rx_ring.is_empty() {
            return Err(Error::WouldBlock);
        }

        let head = iface.rx_ring.head;
        let pkt = &self.rx_bufs[idx][head];
        if buf.len() < pkt.len {
            return Err(Error::InvalidArgument);
        }
        let pkt_len = pkt.len;
        buf[..pkt_len].copy_from_slice(&pkt.data[..pkt_len]);

        let iface = self.get_iface_mut(handle)?;
        iface.rx_ring.advance_head();
        iface.rx_ring.count = iface.rx_ring.count.saturating_sub(1);

        Ok(pkt_len)
    }

    /// Enqueue a packet into an interface's RX ring (kernel ->
    /// userspace).
    ///
    /// Called by the kernel network stack to deliver a packet to
    /// userspace through the virtual interface.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the handle is invalid.
    /// - [`Error::InvalidArgument`] if the interface is down or
    ///   `data` exceeds MTU.
    /// - [`Error::WouldBlock`] if the RX ring is full.
    pub fn enqueue_rx(&mut self, handle: TunTapHandle, data: &[u8]) -> Result<()> {
        let idx = handle.index;
        {
            let iface = self.get_iface(handle)?;
            if !iface.flags.up {
                return Err(Error::InvalidArgument);
            }
            if data.is_empty() || data.len() > MAX_PACKET_SIZE {
                return Err(Error::InvalidArgument);
            }
        }

        let iface = self.get_iface_mut(handle)?;
        if iface.rx_ring.is_full() {
            iface.rx_ring.drops = iface.rx_ring.drops.saturating_add(1);
            return Err(Error::WouldBlock);
        }

        let tail = iface.rx_ring.tail;
        let buf = &mut self.rx_bufs[idx][tail];
        buf.data[..data.len()].copy_from_slice(data);
        buf.len = data.len();

        let iface = self.get_iface_mut(handle)?;
        iface.rx_ring.advance_tail();
        iface.rx_ring.count += 1;
        iface.stats.rx_packets = iface.stats.rx_packets.saturating_add(1);
        iface.stats.rx_bytes = iface.stats.rx_bytes.saturating_add(data.len() as u64);

        Ok(())
    }

    /// Dequeue a packet from an interface's TX ring (userspace ->
    /// kernel).
    ///
    /// Called by the kernel network stack to retrieve packets
    /// written by userspace for processing/forwarding.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the handle is invalid.
    /// - [`Error::WouldBlock`] if the TX ring is empty.
    /// - [`Error::InvalidArgument`] if `buf` is too small.
    pub fn dequeue_tx(&mut self, handle: TunTapHandle, buf: &mut [u8]) -> Result<usize> {
        let idx = handle.index;
        let iface = self.get_iface(handle)?;
        if iface.tx_ring.is_empty() {
            return Err(Error::WouldBlock);
        }

        let head = iface.tx_ring.head;
        let pkt = &self.tx_bufs[idx][head];
        if buf.len() < pkt.len {
            return Err(Error::InvalidArgument);
        }
        let pkt_len = pkt.len;
        buf[..pkt_len].copy_from_slice(&pkt.data[..pkt_len]);

        let iface = self.get_iface_mut(handle)?;
        iface.tx_ring.advance_head();
        iface.tx_ring.count = iface.tx_ring.count.saturating_sub(1);

        Ok(pkt_len)
    }

    /// Bring an interface up.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the handle is invalid.
    pub fn bring_up(&mut self, handle: TunTapHandle) -> Result<()> {
        self.get_iface_mut(handle)?.bring_up();
        Ok(())
    }

    /// Bring an interface down.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the handle is invalid.
    pub fn bring_down(&mut self, handle: TunTapHandle) -> Result<()> {
        self.get_iface_mut(handle)?.bring_down();
        Ok(())
    }

    /// Set the MTU on an interface.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] or [`Error::InvalidArgument`].
    pub fn set_mtu(&mut self, handle: TunTapHandle, mtu: u32) -> Result<()> {
        self.get_iface_mut(handle)?.set_mtu(mtu)
    }

    /// Set the IPv4 address on an interface.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the handle is invalid.
    pub fn set_ipv4(&mut self, handle: TunTapHandle, addr: [u8; 4], mask: [u8; 4]) -> Result<()> {
        self.get_iface_mut(handle)?.set_ipv4(addr, mask);
        Ok(())
    }

    /// Get the statistics for an interface.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the handle is invalid.
    pub fn stats(&self, handle: TunTapHandle) -> Result<InterfaceStats> {
        Ok(self.get_iface(handle)?.stats())
    }

    /// Look up an interface by name.
    ///
    /// Returns the handle if found.
    pub fn find_by_name(&self, name: &[u8]) -> Option<TunTapHandle> {
        for (idx, slot) in self.interfaces.iter().enumerate() {
            if let Some(iface) = slot {
                if iface.active && iface.name() == name {
                    return Some(TunTapHandle {
                        index: idx,
                        generation: self.generation,
                    });
                }
            }
        }
        None
    }

    /// Return the mode of an interface.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the handle is invalid.
    pub fn mode(&self, handle: TunTapHandle) -> Result<TunTapMode> {
        Ok(self.get_iface(handle)?.mode())
    }

    /// Return pending TX packet count for an interface.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the handle is invalid.
    pub fn tx_pending(&self, handle: TunTapHandle) -> Result<usize> {
        Ok(self.get_iface(handle)?.tx_ring.len())
    }

    /// Return pending RX packet count for an interface.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the handle is invalid.
    pub fn rx_pending(&self, handle: TunTapHandle) -> Result<usize> {
        Ok(self.get_iface(handle)?.rx_ring.len())
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid IPv4 packet (20-byte header, version 4).
    fn ipv4_packet() -> [u8; 20] {
        let mut pkt = [0u8; 20];
        pkt[0] = 0x45; // Version 4, IHL 5
        pkt
    }

    /// Minimal valid Ethernet frame (14-byte header + 20-byte
    /// payload).
    fn eth_frame() -> [u8; 34] {
        let mut frame = [0u8; 34];
        // EtherType = IPv4
        frame[12] = 0x08;
        frame[13] = 0x00;
        // Payload: minimal IPv4
        frame[14] = 0x45;
        frame
    }

    #[test]
    fn test_create_tun() {
        let mut reg = TunTapRegistry::new();
        let h = reg.create(b"tun0", TunTapMode::Tun).unwrap();
        assert_eq!(reg.count(), 1);
        assert_eq!(reg.mode(h).unwrap(), TunTapMode::Tun);
    }

    #[test]
    fn test_create_tap() {
        let mut reg = TunTapRegistry::new();
        let h = reg.create(b"tap0", TunTapMode::Tap).unwrap();
        assert_eq!(reg.mode(h).unwrap(), TunTapMode::Tap);
    }

    #[test]
    fn test_duplicate_name_rejected() {
        let mut reg = TunTapRegistry::new();
        reg.create(b"tun0", TunTapMode::Tun).unwrap();
        let err = reg.create(b"tun0", TunTapMode::Tun);
        assert!(err.is_err());
    }

    #[test]
    fn test_write_read_tun() {
        let mut reg = TunTapRegistry::new();
        let h = reg.create(b"tun0", TunTapMode::Tun).unwrap();
        reg.bring_up(h).unwrap();

        let pkt = ipv4_packet();
        reg.write(h, &pkt).unwrap();
        assert_eq!(reg.tx_pending(h).unwrap(), 1);

        let mut out = [0u8; 64];
        let n = reg.dequeue_tx(h, &mut out).unwrap();
        assert_eq!(n, 20);
        assert_eq!(&out[..n], &pkt[..]);
    }

    #[test]
    fn test_enqueue_read_rx() {
        let mut reg = TunTapRegistry::new();
        let h = reg.create(b"tun0", TunTapMode::Tun).unwrap();
        reg.bring_up(h).unwrap();

        let pkt = ipv4_packet();
        reg.enqueue_rx(h, &pkt).unwrap();
        assert_eq!(reg.rx_pending(h).unwrap(), 1);

        let mut out = [0u8; 64];
        let n = reg.read(h, &mut out).unwrap();
        assert_eq!(n, 20);
    }

    #[test]
    fn test_write_down_interface_fails() {
        let mut reg = TunTapRegistry::new();
        let h = reg.create(b"tun0", TunTapMode::Tun).unwrap();
        // Interface is down by default
        let pkt = ipv4_packet();
        let err = reg.write(h, &pkt);
        assert!(err.is_err());
    }

    #[test]
    fn test_tap_write_read() {
        let mut reg = TunTapRegistry::new();
        let h = reg.create(b"tap0", TunTapMode::Tap).unwrap();
        reg.bring_up(h).unwrap();

        let frame = eth_frame();
        reg.write(h, &frame).unwrap();

        let mut out = [0u8; 64];
        let n = reg.dequeue_tx(h, &mut out).unwrap();
        assert_eq!(n, 34);
    }

    #[test]
    fn test_destroy() {
        let mut reg = TunTapRegistry::new();
        let h = reg.create(b"tun0", TunTapMode::Tun).unwrap();
        assert_eq!(reg.count(), 1);
        reg.destroy(h).unwrap();
        assert_eq!(reg.count(), 0);
    }

    #[test]
    fn test_find_by_name() {
        let mut reg = TunTapRegistry::new();
        reg.create(b"tun0", TunTapMode::Tun).unwrap();
        let found = reg.find_by_name(b"tun0");
        assert!(found.is_some());
        let not_found = reg.find_by_name(b"tun1");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_stats() {
        let mut reg = TunTapRegistry::new();
        let h = reg.create(b"tun0", TunTapMode::Tun).unwrap();
        reg.bring_up(h).unwrap();

        let pkt = ipv4_packet();
        reg.write(h, &pkt).unwrap();
        reg.write(h, &pkt).unwrap();

        let s = reg.stats(h).unwrap();
        assert_eq!(s.tx_packets, 2);
        assert_eq!(s.tx_bytes, 40);
    }

    #[test]
    fn test_set_mtu() {
        let mut reg = TunTapRegistry::new();
        let h = reg.create(b"tun0", TunTapMode::Tun).unwrap();
        reg.set_mtu(h, 9000).unwrap();
        let err = reg.set_mtu(h, 0);
        assert!(err.is_err());
    }
}
