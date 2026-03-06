// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IPVLAN virtual network device subsystem.
//!
//! IPVLAN allows creation of virtual network interfaces that share the
//! parent (master) device's MAC address but have distinct IP addresses.
//! Unlike MACVLAN (which assigns unique MACs), IPVLAN multiplexes at
//! the IP layer, making it more suitable for environments with MAC
//! address restrictions (e.g., some cloud providers, 802.1X networks).
//!
//! # Modes
//!
//! | Mode | Description                                              |
//! |------|----------------------------------------------------------|
//! | L2   | Bridge-like forwarding using L2 headers (default)        |
//! | L3   | IP routing between slaves (no L2 header inspection)      |
//! | L3S  | L3 with source address validation (conntrack-friendly)   |
//!
//! # Architecture
//!
//! ```text
//! ┌──────────┐  ┌──────────┐  ┌──────────┐
//! │ slave0   │  │ slave1   │  │ slave2   │   (virtual interfaces)
//! └────┬─────┘  └────┬─────┘  └────┬─────┘
//!      │             │             │
//!      └──────┬──────┴──────┬──────┘
//!             │   ipvlan    │
//!             │   port      │
//!             └──────┬──────┘
//!                    │
//!             ┌──────┴──────┐
//!             │   master    │   (physical NIC)
//!             │   eth0      │
//!             └─────────────┘
//! ```
//!
//! # Reference
//!
//! Linux kernel `drivers/net/ipvlan/`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of IPVLAN ports (master devices).
const MAX_PORTS: usize = 16;

/// Maximum number of slave interfaces per port.
const MAX_SLAVES_PER_PORT: usize = 32;

/// Maximum number of IP addresses per slave.
const MAX_ADDRS_PER_SLAVE: usize = 8;

/// Maximum number of multicast groups per slave.
const MAX_MCAST_GROUPS: usize = 16;

/// Maximum MTU.
const MAX_MTU: u32 = 65535;

/// Minimum MTU (IPv4 minimum).
const MIN_MTU: u32 = 68;

/// Default MTU.
const DEFAULT_MTU: u32 = 1500;

/// Maximum interface name length.
const MAX_IFNAME_LEN: usize = 16;

/// Maximum MAC address length (Ethernet).
const MAC_ADDR_LEN: usize = 6;

// ── IpvlanMode ────────────────────────────────────────────────────────────────

/// IPVLAN operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IpvlanMode {
    /// L2 mode: bridge-like switching using L2 headers.
    #[default]
    L2,
    /// L3 mode: IP-layer routing between slaves.
    L3,
    /// L3S mode: L3 with source address validation.
    L3S,
}

// ── IpvlanFlags ───────────────────────────────────────────────────────────────

/// IPVLAN configuration flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct IpvlanFlags {
    /// Enable bridge mode (L2 only: forward between slaves).
    pub bridge: bool,
    /// Enable private mode (no inter-slave communication).
    pub private: bool,
    /// Enable VEPA mode (all traffic goes via external switch).
    pub vepa: bool,
}

impl IpvlanFlags {
    /// Create default flags.
    pub const fn new() -> Self {
        Self {
            bridge: false,
            private: false,
            vepa: false,
        }
    }
}

// ── IpAddress ─────────────────────────────────────────────────────────────────

/// An IP address assigned to an IPVLAN slave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpAddress {
    /// IPv4 address (4 bytes).
    V4([u8; 4]),
    /// IPv6 address (16 bytes).
    V6([u8; 16]),
}

impl IpAddress {
    /// Check if this is an IPv4 address.
    pub const fn is_v4(&self) -> bool {
        matches!(self, Self::V4(_))
    }

    /// Check if this is an IPv6 address.
    pub const fn is_v6(&self) -> bool {
        matches!(self, Self::V6(_))
    }

    /// Check if this is a multicast address.
    pub const fn is_multicast(&self) -> bool {
        match self {
            Self::V4(addr) => addr[0] >= 224 && addr[0] <= 239,
            Self::V6(addr) => addr[0] == 0xff,
        }
    }

    /// Check if this is a broadcast address.
    pub const fn is_broadcast(&self) -> bool {
        match self {
            Self::V4(addr) => addr[0] == 255 && addr[1] == 255 && addr[2] == 255 && addr[3] == 255,
            Self::V6(_) => false, // IPv6 has no broadcast
        }
    }
}

// ── IpvlanStats ───────────────────────────────────────────────────────────────

/// Traffic statistics for an IPVLAN interface.
#[derive(Debug, Clone, Copy)]
pub struct IpvlanStats {
    /// Packets received.
    pub rx_packets: u64,
    /// Bytes received.
    pub rx_bytes: u64,
    /// Packets transmitted.
    pub tx_packets: u64,
    /// Bytes transmitted.
    pub tx_bytes: u64,
    /// Receive errors.
    pub rx_errors: u64,
    /// Transmit errors.
    pub tx_errors: u64,
    /// Dropped packets (rx).
    pub rx_dropped: u64,
    /// Dropped packets (tx).
    pub tx_dropped: u64,
    /// Multicast packets received.
    pub multicast: u64,
}

impl IpvlanStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            rx_packets: 0,
            rx_bytes: 0,
            tx_packets: 0,
            tx_bytes: 0,
            rx_errors: 0,
            tx_errors: 0,
            rx_dropped: 0,
            tx_dropped: 0,
            multicast: 0,
        }
    }

    /// Record a received packet.
    pub fn record_rx(&mut self, bytes: u64) {
        self.rx_packets += 1;
        self.rx_bytes = self.rx_bytes.saturating_add(bytes);
    }

    /// Record a transmitted packet.
    pub fn record_tx(&mut self, bytes: u64) {
        self.tx_packets += 1;
        self.tx_bytes = self.tx_bytes.saturating_add(bytes);
    }

    /// Record a receive error.
    pub fn record_rx_error(&mut self) {
        self.rx_errors += 1;
    }

    /// Record a transmit error.
    pub fn record_tx_error(&mut self) {
        self.tx_errors += 1;
    }

    /// Record a receive drop.
    pub fn record_rx_drop(&mut self) {
        self.rx_dropped += 1;
    }

    /// Record a transmit drop.
    pub fn record_tx_drop(&mut self) {
        self.tx_dropped += 1;
    }

    /// Record a multicast receive.
    pub fn record_multicast(&mut self) {
        self.multicast += 1;
    }

    /// Reset all counters.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

impl Default for IpvlanStats {
    fn default() -> Self {
        Self::new()
    }
}

// ── IpvlanSlave ───────────────────────────────────────────────────────────────

/// An IPVLAN slave (virtual) interface.
///
/// Each slave has its own IP address(es) but shares the master's
/// MAC address. Traffic is demultiplexed by IP address.
pub struct IpvlanSlave {
    /// Interface name (e.g., "ipvl0").
    ifname: [u8; MAX_IFNAME_LEN],
    /// Name length.
    ifname_len: usize,
    /// Interface index.
    ifindex: u32,
    /// Assigned IP addresses.
    addrs: [Option<IpAddress>; MAX_ADDRS_PER_SLAVE],
    /// Number of addresses.
    addr_count: usize,
    /// Joined multicast groups.
    mcast_groups: [Option<IpAddress>; MAX_MCAST_GROUPS],
    /// Number of multicast groups.
    mcast_count: usize,
    /// Traffic statistics.
    stats: IpvlanStats,
    /// MTU.
    mtu: u32,
    /// Whether the interface is up.
    link_up: bool,
    /// Whether this slot is active.
    active: bool,
}

impl IpvlanSlave {
    /// Create an empty (inactive) slave.
    pub const fn new() -> Self {
        Self {
            ifname: [0u8; MAX_IFNAME_LEN],
            ifname_len: 0,
            ifindex: 0,
            addrs: [const { None }; MAX_ADDRS_PER_SLAVE],
            addr_count: 0,
            mcast_groups: [const { None }; MAX_MCAST_GROUPS],
            mcast_count: 0,
            stats: IpvlanStats::new(),
            mtu: DEFAULT_MTU,
            link_up: false,
            active: false,
        }
    }

    /// Get the interface name.
    pub fn ifname(&self) -> &[u8] {
        &self.ifname[..self.ifname_len]
    }

    /// Get the interface index.
    pub const fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// Check if the link is up.
    pub const fn is_link_up(&self) -> bool {
        self.link_up
    }

    /// Get a reference to the statistics.
    pub const fn stats(&self) -> &IpvlanStats {
        &self.stats
    }

    /// Get the MTU.
    pub const fn mtu(&self) -> u32 {
        self.mtu
    }

    /// Get the number of assigned addresses.
    pub const fn addr_count(&self) -> usize {
        self.addr_count
    }

    /// Add an IP address to this slave.
    pub fn add_addr(&mut self, addr: IpAddress) -> Result<()> {
        if self.addr_count >= MAX_ADDRS_PER_SLAVE {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate.
        for i in 0..self.addr_count {
            if let Some(existing) = &self.addrs[i] {
                if *existing == addr {
                    return Err(Error::AlreadyExists);
                }
            }
        }
        self.addrs[self.addr_count] = Some(addr);
        self.addr_count += 1;
        Ok(())
    }

    /// Remove an IP address from this slave.
    pub fn remove_addr(&mut self, addr: &IpAddress) -> Result<()> {
        for i in 0..self.addr_count {
            if let Some(existing) = &self.addrs[i] {
                if existing == addr {
                    // Shift remaining.
                    for j in i..self.addr_count.saturating_sub(1) {
                        self.addrs[j] = self.addrs[j + 1];
                    }
                    self.addrs[self.addr_count - 1] = None;
                    self.addr_count -= 1;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Check if this slave owns a given IP address.
    pub fn has_addr(&self, addr: &IpAddress) -> bool {
        for i in 0..self.addr_count {
            if let Some(existing) = &self.addrs[i] {
                if existing == addr {
                    return true;
                }
            }
        }
        false
    }

    /// Join a multicast group.
    pub fn join_mcast(&mut self, group: IpAddress) -> Result<()> {
        if !group.is_multicast() {
            return Err(Error::InvalidArgument);
        }
        if self.mcast_count >= MAX_MCAST_GROUPS {
            return Err(Error::OutOfMemory);
        }
        for i in 0..self.mcast_count {
            if let Some(existing) = &self.mcast_groups[i] {
                if *existing == group {
                    return Err(Error::AlreadyExists);
                }
            }
        }
        self.mcast_groups[self.mcast_count] = Some(group);
        self.mcast_count += 1;
        Ok(())
    }

    /// Leave a multicast group.
    pub fn leave_mcast(&mut self, group: &IpAddress) -> Result<()> {
        for i in 0..self.mcast_count {
            if let Some(existing) = &self.mcast_groups[i] {
                if existing == group {
                    for j in i..self.mcast_count.saturating_sub(1) {
                        self.mcast_groups[j] = self.mcast_groups[j + 1];
                    }
                    self.mcast_groups[self.mcast_count - 1] = None;
                    self.mcast_count -= 1;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Set link state.
    pub fn set_link_up(&mut self, up: bool) {
        self.link_up = up;
    }

    /// Set MTU.
    pub fn set_mtu(&mut self, mtu: u32) -> Result<()> {
        if mtu < MIN_MTU || mtu > MAX_MTU {
            return Err(Error::InvalidArgument);
        }
        self.mtu = mtu;
        Ok(())
    }

    /// Process a received frame.
    pub fn rx_frame(&mut self, bytes: u64) {
        if self.link_up {
            self.stats.record_rx(bytes);
        } else {
            self.stats.record_rx_drop();
        }
    }

    /// Process a transmitted frame.
    pub fn tx_frame(&mut self, bytes: u64) -> Result<()> {
        if !self.link_up {
            self.stats.record_tx_drop();
            return Err(Error::IoError);
        }
        self.stats.record_tx(bytes);
        Ok(())
    }
}

impl Default for IpvlanSlave {
    fn default() -> Self {
        Self::new()
    }
}

// ── IpvlanPort ────────────────────────────────────────────────────────────────

/// An IPVLAN port attached to a master (physical) device.
///
/// Manages slave interfaces and handles frame demultiplexing.
pub struct IpvlanPort {
    /// Master device interface name.
    master_ifname: [u8; MAX_IFNAME_LEN],
    /// Master name length.
    master_ifname_len: usize,
    /// Master device interface index.
    master_ifindex: u32,
    /// Master device MAC address.
    master_mac: [u8; MAC_ADDR_LEN],
    /// Operating mode.
    mode: IpvlanMode,
    /// Configuration flags.
    flags: IpvlanFlags,
    /// Slave interfaces.
    slaves: [IpvlanSlave; MAX_SLAVES_PER_PORT],
    /// Number of active slaves.
    slave_count: usize,
    /// Next interface index to assign.
    next_ifindex: u32,
    /// Whether this port is active.
    active: bool,
}

impl IpvlanPort {
    /// Create an empty (inactive) port.
    pub const fn new() -> Self {
        Self {
            master_ifname: [0u8; MAX_IFNAME_LEN],
            master_ifname_len: 0,
            master_ifindex: 0,
            master_mac: [0u8; MAC_ADDR_LEN],
            mode: IpvlanMode::L2,
            flags: IpvlanFlags::new(),
            slaves: [const { IpvlanSlave::new() }; MAX_SLAVES_PER_PORT],
            slave_count: 0,
            next_ifindex: 1,
            active: false,
        }
    }

    /// Initialize the port for a master device.
    pub fn init(
        &mut self,
        ifname: &[u8],
        ifindex: u32,
        mac: &[u8; MAC_ADDR_LEN],
        mode: IpvlanMode,
    ) -> Result<()> {
        if ifname.is_empty() || ifname.len() > MAX_IFNAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let len = ifname.len().min(MAX_IFNAME_LEN);
        self.master_ifname[..len].copy_from_slice(&ifname[..len]);
        self.master_ifname_len = len;
        self.master_ifindex = ifindex;
        self.master_mac = *mac;
        self.mode = mode;
        self.active = true;
        self.slave_count = 0;
        self.next_ifindex = ifindex + 1;
        Ok(())
    }

    /// Get the operating mode.
    pub const fn mode(&self) -> IpvlanMode {
        self.mode
    }

    /// Set the operating mode.
    pub fn set_mode(&mut self, mode: IpvlanMode) {
        self.mode = mode;
    }

    /// Get the master MAC address.
    pub const fn master_mac(&self) -> &[u8; MAC_ADDR_LEN] {
        &self.master_mac
    }

    /// Get the master interface name.
    pub fn master_ifname(&self) -> &[u8] {
        &self.master_ifname[..self.master_ifname_len]
    }

    /// Number of active slaves.
    pub const fn slave_count(&self) -> usize {
        self.slave_count
    }

    /// Create a new slave interface.
    ///
    /// Returns the slave index.
    pub fn create_slave(&mut self, ifname: &[u8]) -> Result<usize> {
        if !self.active {
            return Err(Error::NotFound);
        }
        if self.slave_count >= MAX_SLAVES_PER_PORT {
            return Err(Error::OutOfMemory);
        }
        if ifname.is_empty() || ifname.len() > MAX_IFNAME_LEN {
            return Err(Error::InvalidArgument);
        }

        let slot = self.find_free_slave_slot()?;
        let slave = &mut self.slaves[slot];
        let len = ifname.len().min(MAX_IFNAME_LEN);
        slave.ifname[..len].copy_from_slice(&ifname[..len]);
        slave.ifname_len = len;
        slave.ifindex = self.next_ifindex;
        self.next_ifindex += 1;
        slave.mtu = DEFAULT_MTU;
        slave.active = true;
        slave.link_up = true;
        if slot >= self.slave_count {
            self.slave_count = slot + 1;
        }
        Ok(slot)
    }

    /// Destroy a slave interface.
    pub fn destroy_slave(&mut self, idx: usize) -> Result<()> {
        if idx >= self.slave_count || !self.slaves[idx].active {
            return Err(Error::NotFound);
        }
        self.slaves[idx].active = false;
        self.slaves[idx].link_up = false;
        self.slaves[idx].addr_count = 0;
        self.slaves[idx].mcast_count = 0;
        Ok(())
    }

    /// Get a reference to a slave.
    pub fn get_slave(&self, idx: usize) -> Result<&IpvlanSlave> {
        if idx >= self.slave_count || !self.slaves[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&self.slaves[idx])
    }

    /// Get a mutable reference to a slave.
    pub fn get_slave_mut(&mut self, idx: usize) -> Result<&mut IpvlanSlave> {
        if idx >= self.slave_count || !self.slaves[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&mut self.slaves[idx])
    }

    /// Receive a frame from the master device and dispatch to the
    /// appropriate slave based on destination IP.
    ///
    /// Returns the slave index that received the frame, or NotFound
    /// if no slave owns the destination address.
    pub fn rx_dispatch(&mut self, dst_addr: &IpAddress, frame_bytes: u64) -> Result<usize> {
        if !self.active {
            return Err(Error::NotFound);
        }

        // Multicast: deliver to all slaves that joined the group.
        if dst_addr.is_multicast() {
            let mut delivered = false;
            for i in 0..self.slave_count {
                if self.slaves[i].active {
                    self.slaves[i].rx_frame(frame_bytes);
                    self.slaves[i].stats.record_multicast();
                    delivered = true;
                }
            }
            if delivered {
                return Ok(0); // multicast — no single target
            }
            return Err(Error::NotFound);
        }

        // Broadcast: deliver to all slaves.
        if dst_addr.is_broadcast() {
            for i in 0..self.slave_count {
                if self.slaves[i].active {
                    self.slaves[i].rx_frame(frame_bytes);
                }
            }
            return Ok(0);
        }

        // Unicast: find the slave that owns this IP.
        for i in 0..self.slave_count {
            if self.slaves[i].active && self.slaves[i].has_addr(dst_addr) {
                self.slaves[i].rx_frame(frame_bytes);
                return Ok(i);
            }
        }

        Err(Error::NotFound)
    }

    /// Transmit a frame from a slave via the master device.
    ///
    /// In L2 mode, inter-slave traffic is handled locally.
    /// In L3/L3S mode, traffic is routed.
    pub fn tx_frame(
        &mut self,
        src_slave_idx: usize,
        dst_addr: &IpAddress,
        frame_bytes: u64,
    ) -> Result<()> {
        if !self.active {
            return Err(Error::NotFound);
        }
        if src_slave_idx >= self.slave_count || !self.slaves[src_slave_idx].active {
            return Err(Error::NotFound);
        }

        // L2 mode: check for local delivery first.
        if self.mode == IpvlanMode::L2 && !self.flags.private {
            for i in 0..self.slave_count {
                if i != src_slave_idx && self.slaves[i].active && self.slaves[i].has_addr(dst_addr)
                {
                    // Local delivery (hairpin).
                    self.slaves[i].rx_frame(frame_bytes);
                    self.slaves[src_slave_idx].stats.record_tx(frame_bytes);
                    return Ok(());
                }
            }
        }

        // Send via master (external).
        self.slaves[src_slave_idx].tx_frame(frame_bytes)
    }

    /// Find a free slave slot.
    fn find_free_slave_slot(&self) -> Result<usize> {
        for i in 0..self.slave_count {
            if !self.slaves[i].active {
                return Ok(i);
            }
        }
        if self.slave_count < MAX_SLAVES_PER_PORT {
            return Ok(self.slave_count);
        }
        Err(Error::OutOfMemory)
    }

    /// Get aggregate statistics across all slaves.
    pub fn aggregate_stats(&self) -> IpvlanStats {
        let mut agg = IpvlanStats::new();
        for i in 0..self.slave_count {
            if self.slaves[i].active {
                let s = &self.slaves[i].stats;
                agg.rx_packets += s.rx_packets;
                agg.rx_bytes += s.rx_bytes;
                agg.tx_packets += s.tx_packets;
                agg.tx_bytes += s.tx_bytes;
                agg.rx_errors += s.rx_errors;
                agg.tx_errors += s.tx_errors;
                agg.rx_dropped += s.rx_dropped;
                agg.tx_dropped += s.tx_dropped;
                agg.multicast += s.multicast;
            }
        }
        agg
    }
}

impl Default for IpvlanPort {
    fn default() -> Self {
        Self::new()
    }
}

// ── IpvlanManager ─────────────────────────────────────────────────────────────

/// Global IPVLAN port manager.
///
/// Tracks all master-device ports and provides lookup operations.
pub struct IpvlanManager {
    /// All ports.
    ports: [IpvlanPort; MAX_PORTS],
    /// Number of used port slots.
    count: usize,
}

impl IpvlanManager {
    /// Create an empty manager.
    pub const fn new() -> Self {
        Self {
            ports: [const { IpvlanPort::new() }; MAX_PORTS],
            count: 0,
        }
    }

    /// Create a new port for a master device.
    ///
    /// Returns the port index.
    pub fn create_port(
        &mut self,
        ifname: &[u8],
        ifindex: u32,
        mac: &[u8; MAC_ADDR_LEN],
        mode: IpvlanMode,
    ) -> Result<usize> {
        if self.count >= MAX_PORTS {
            return Err(Error::OutOfMemory);
        }

        let slot = self.find_free_port_slot()?;
        self.ports[slot].init(ifname, ifindex, mac, mode)?;
        if slot >= self.count {
            self.count = slot + 1;
        }
        Ok(slot)
    }

    /// Destroy a port and all its slaves.
    pub fn destroy_port(&mut self, idx: usize) -> Result<()> {
        if idx >= self.count || !self.ports[idx].active {
            return Err(Error::NotFound);
        }
        self.ports[idx].active = false;
        self.ports[idx].slave_count = 0;
        Ok(())
    }

    /// Get a reference to a port.
    pub fn get_port(&self, idx: usize) -> Result<&IpvlanPort> {
        if idx >= self.count || !self.ports[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&self.ports[idx])
    }

    /// Get a mutable reference to a port.
    pub fn get_port_mut(&mut self, idx: usize) -> Result<&mut IpvlanPort> {
        if idx >= self.count || !self.ports[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&mut self.ports[idx])
    }

    /// Number of active ports.
    pub fn active_count(&self) -> usize {
        let mut n = 0;
        for i in 0..self.count {
            if self.ports[i].active {
                n += 1;
            }
        }
        n
    }

    /// Find a free port slot.
    fn find_free_port_slot(&self) -> Result<usize> {
        for i in 0..self.count {
            if !self.ports[i].active {
                return Ok(i);
            }
        }
        if self.count < MAX_PORTS {
            return Ok(self.count);
        }
        Err(Error::OutOfMemory)
    }
}

impl Default for IpvlanManager {
    fn default() -> Self {
        Self::new()
    }
}
