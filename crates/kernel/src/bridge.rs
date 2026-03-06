// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Network bridge (IEEE 802.1D) for the ONCRIX kernel.
//!
//! Implements a learning Ethernet bridge that forwards frames between
//! ports based on MAC address lookups in a forwarding database (FDB).
//! Ports participate in a simplified Spanning Tree Protocol (STP)
//! state machine to prevent loops.
//!
//! # Architecture
//!
//! ```text
//! incoming frame on port P
//!        |
//!        v
//! BridgeDevice::learn(src_mac, port P)  ← update FDB
//!        |
//!        v
//! BridgeDevice::lookup(dst_mac)
//!        |
//!        ├─ found → forward to destination port
//!        |
//!        └─ not found → flood to all forwarding ports (except P)
//! ```
//!
//! Key components:
//!
//! - [`BridgePortState`]: STP port states (Disabled, Listening,
//!   Learning, Forwarding, Blocking).
//! - [`BridgePort`]: a single bridge port with MAC address, STP
//!   state, and configuration.
//! - [`FdbEntry`]: forwarding database entry mapping a MAC address
//!   to a port with ageing support.
//! - [`BridgeDevice`]: a complete bridge instance with ports, FDB,
//!   and forwarding logic.
//! - [`BridgeRegistry`]: system-wide registry managing up to
//!   [`MAX_BRIDGES`] bridge instances.
//!
//! Reference: IEEE 802.1D-2004 (MAC Bridges).

use oncrix_lib::{Error, Result};

// =========================================================================
// Constants
// =========================================================================

/// Maximum number of bridges in the system registry.
const MAX_BRIDGES: usize = 8;

/// Maximum number of ports per bridge.
const MAX_PORTS: usize = 8;

/// Maximum number of forwarding database entries per bridge.
const MAX_FDB_ENTRIES: usize = 256;

/// Default FDB ageing time in ticks (300 ticks, analogous to the
/// 802.1D default of 300 seconds with 1-second ticks).
const DEFAULT_AGEING_TIME: u32 = 300;

/// Ethernet address length in bytes.
const ETH_ALEN: usize = 6;

/// Minimum Ethernet frame size (without FCS).
const MIN_FRAME_LEN: usize = 14;

// =========================================================================
// BridgePortState
// =========================================================================

/// Spanning Tree Protocol port state.
///
/// Determines how a bridge port handles received frames per
/// IEEE 802.1D section 8.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BridgePortState {
    /// Port is administratively disabled — no frames are
    /// processed.
    #[default]
    Disabled,
    /// Port is listening for BPDUs but does not learn MAC addresses
    /// or forward data frames.
    Listening,
    /// Port is learning MAC addresses from received frames but
    /// does not forward data frames.
    Learning,
    /// Port is fully operational — learns MAC addresses and
    /// forwards data frames.
    Forwarding,
    /// Port is blocking to prevent loops — only processes BPDUs.
    Blocking,
}

impl BridgePortState {
    /// Return whether this state allows MAC address learning.
    pub const fn can_learn(self) -> bool {
        matches!(self, Self::Learning | Self::Forwarding)
    }

    /// Return whether this state allows data frame forwarding.
    pub const fn can_forward(self) -> bool {
        matches!(self, Self::Forwarding)
    }
}

// =========================================================================
// BridgePort
// =========================================================================

/// A single bridge port.
///
/// Each port has its own MAC address, STP state, and configuration.
/// A port can participate in STP if [`stp_enabled`](Self::stp_enabled)
/// is set.
#[derive(Debug, Clone, Copy)]
pub struct BridgePort {
    /// Port identifier (unique within the bridge, 1-based).
    pub port_id: u8,
    /// STP port state.
    pub state: BridgePortState,
    /// MAC address of the physical interface backing this port.
    pub mac_addr: [u8; ETH_ALEN],
    /// Whether STP is enabled on this port.
    pub stp_enabled: bool,
    /// Whether this port slot is in use.
    in_use: bool,
}

impl BridgePort {
    /// An empty, unused port slot.
    const EMPTY: Self = Self {
        port_id: 0,
        state: BridgePortState::Disabled,
        mac_addr: [0u8; ETH_ALEN],
        stp_enabled: false,
        in_use: false,
    };

    /// Create a new bridge port in the Disabled state.
    pub const fn new(port_id: u8, mac_addr: [u8; ETH_ALEN]) -> Self {
        Self {
            port_id,
            state: BridgePortState::Disabled,
            mac_addr,
            stp_enabled: false,
            in_use: false,
        }
    }
}

// =========================================================================
// FdbEntry
// =========================================================================

/// Forwarding database entry.
///
/// Maps a learned or statically configured MAC address to a bridge
/// port.  Dynamic entries are subject to ageing: they are removed
/// when `aging_timer` reaches zero after not being refreshed.
#[derive(Debug, Clone, Copy)]
pub struct FdbEntry {
    /// MAC address that this entry maps.
    pub mac_addr: [u8; ETH_ALEN],
    /// Port ID to which this MAC address is mapped.
    pub port_id: u8,
    /// Whether this is a static (permanent) entry.
    pub is_static: bool,
    /// Remaining ageing ticks before this entry expires (dynamic
    /// entries only).
    pub aging_timer: u32,
    /// Tick counter at which this entry was last refreshed.
    pub last_seen: u64,
    /// Whether this FDB slot is in use.
    in_use: bool,
}

impl FdbEntry {
    /// An empty, unused FDB slot.
    const EMPTY: Self = Self {
        mac_addr: [0u8; ETH_ALEN],
        port_id: 0,
        is_static: false,
        aging_timer: 0,
        last_seen: 0,
        in_use: false,
    };
}

// =========================================================================
// BridgeDevice
// =========================================================================

/// A network bridge device.
///
/// Manages a set of ports and a forwarding database.  Incoming
/// frames are learned (source MAC) and either forwarded to a known
/// destination port or flooded to all forwarding ports.
pub struct BridgeDevice {
    /// Bridge identifier (assigned by [`BridgeRegistry`]).
    pub bridge_id: u32,
    /// Bridge ports.
    ports: [BridgePort; MAX_PORTS],
    /// Forwarding database.
    fdb: [FdbEntry; MAX_FDB_ENTRIES],
    /// FDB ageing time in ticks.
    pub ageing_time: u32,
    /// Current tick counter (monotonically increasing).
    tick_counter: u64,
    /// Whether this bridge slot is in use.
    in_use: bool,
}

impl BridgeDevice {
    /// Create a new bridge with default ageing time.
    const fn new(bridge_id: u32) -> Self {
        Self {
            bridge_id,
            ports: [BridgePort::EMPTY; MAX_PORTS],
            fdb: [FdbEntry::EMPTY; MAX_FDB_ENTRIES],
            ageing_time: DEFAULT_AGEING_TIME,
            tick_counter: 0,
            in_use: false,
        }
    }

    /// An empty, unused bridge slot.
    const EMPTY: Self = Self::new(0);

    /// Add a port to the bridge.
    ///
    /// The port starts in [`BridgePortState::Forwarding`] by default
    /// for immediate usability.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if all port slots are occupied.
    /// - [`Error::AlreadyExists`] if a port with the same `port_id`
    ///   is already present.
    pub fn add_port(&mut self, port_id: u8, mac_addr: [u8; ETH_ALEN]) -> Result<()> {
        // Check for duplicate port_id.
        for i in 0..MAX_PORTS {
            if self.ports[i].in_use && self.ports[i].port_id == port_id {
                return Err(Error::AlreadyExists);
            }
        }

        for i in 0..MAX_PORTS {
            if !self.ports[i].in_use {
                self.ports[i] = BridgePort::new(port_id, mac_addr);
                self.ports[i].in_use = true;
                self.ports[i].state = BridgePortState::Forwarding;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a port from the bridge by port ID.
    ///
    /// Also removes all FDB entries associated with the port.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the port does not exist.
    pub fn remove_port(&mut self, port_id: u8) -> Result<()> {
        let mut found = false;
        for i in 0..MAX_PORTS {
            if self.ports[i].in_use && self.ports[i].port_id == port_id {
                self.ports[i].in_use = false;
                found = true;
                break;
            }
        }
        if !found {
            return Err(Error::NotFound);
        }

        // Flush FDB entries for this port.
        for i in 0..MAX_FDB_ENTRIES {
            if self.fdb[i].in_use && self.fdb[i].port_id == port_id {
                self.fdb[i].in_use = false;
            }
        }

        Ok(())
    }

    /// Learn a source MAC address on a port.
    ///
    /// If the MAC address is already in the FDB, updates the port
    /// association and refreshes the ageing timer.  Otherwise
    /// allocates a new FDB entry.  If the FDB is full, the oldest
    /// dynamic entry is evicted.
    ///
    /// Static entries are never overwritten by learning.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the port is not in a
    /// state that allows learning.
    pub fn learn(&mut self, mac_addr: &[u8; ETH_ALEN], port_id: u8) -> Result<()> {
        // Verify the port exists and can learn.
        let port = self.find_port(port_id)?;
        if !port.state.can_learn() {
            return Err(Error::InvalidArgument);
        }

        // Check if already known.
        for i in 0..MAX_FDB_ENTRIES {
            if self.fdb[i].in_use && self.fdb[i].mac_addr == *mac_addr {
                if self.fdb[i].is_static {
                    // Do not overwrite static entries.
                    return Ok(());
                }
                self.fdb[i].port_id = port_id;
                self.fdb[i].aging_timer = self.ageing_time;
                self.fdb[i].last_seen = self.tick_counter;
                return Ok(());
            }
        }

        // Find a free slot.
        for i in 0..MAX_FDB_ENTRIES {
            if !self.fdb[i].in_use {
                self.fdb[i].mac_addr = *mac_addr;
                self.fdb[i].port_id = port_id;
                self.fdb[i].is_static = false;
                self.fdb[i].aging_timer = self.ageing_time;
                self.fdb[i].last_seen = self.tick_counter;
                self.fdb[i].in_use = true;
                return Ok(());
            }
        }

        // FDB full — evict the oldest dynamic entry.
        let mut oldest_idx: Option<usize> = None;
        let mut oldest_seen = u64::MAX;
        for i in 0..MAX_FDB_ENTRIES {
            if self.fdb[i].in_use && !self.fdb[i].is_static && self.fdb[i].last_seen < oldest_seen {
                oldest_seen = self.fdb[i].last_seen;
                oldest_idx = Some(i);
            }
        }

        if let Some(idx) = oldest_idx {
            self.fdb[idx].mac_addr = *mac_addr;
            self.fdb[idx].port_id = port_id;
            self.fdb[idx].is_static = false;
            self.fdb[idx].aging_timer = self.ageing_time;
            self.fdb[idx].last_seen = self.tick_counter;
            self.fdb[idx].in_use = true;
            Ok(())
        } else {
            // All entries are static — cannot evict.
            Err(Error::OutOfMemory)
        }
    }

    /// Look up a destination MAC address in the FDB.
    ///
    /// Returns the port ID if found, or `None` if the MAC address is
    /// unknown (the caller should flood).
    pub fn lookup(&self, mac_addr: &[u8; ETH_ALEN]) -> Option<u8> {
        for i in 0..MAX_FDB_ENTRIES {
            if self.fdb[i].in_use && self.fdb[i].mac_addr == *mac_addr {
                return Some(self.fdb[i].port_id);
            }
        }
        None
    }

    /// Determine forwarding for an incoming frame.
    ///
    /// Performs source MAC learning and destination MAC lookup.
    /// Returns the list of destination port IDs.  If the destination
    /// is known, a single port is returned.  If unknown (or
    /// broadcast/multicast), all forwarding ports except the ingress
    /// port are returned (flood).
    ///
    /// The `ports_out` buffer receives the destination port IDs;
    /// the return value is the number of ports written.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the frame is too short to
    ///   contain Ethernet header fields (14 bytes minimum), or the
    ///   ingress port is not in a forwarding state.
    pub fn forward(
        &mut self,
        frame: &[u8],
        ingress_port: u8,
        ports_out: &mut [u8; MAX_PORTS],
    ) -> Result<usize> {
        if frame.len() < MIN_FRAME_LEN {
            return Err(Error::InvalidArgument);
        }

        // Verify ingress port can forward.
        let ing_port = self.find_port(ingress_port)?;
        if !ing_port.state.can_forward() {
            return Err(Error::InvalidArgument);
        }

        // Extract source and destination MAC from the Ethernet header.
        let mut dst_mac = [0u8; ETH_ALEN];
        let mut src_mac = [0u8; ETH_ALEN];
        dst_mac.copy_from_slice(&frame[0..ETH_ALEN]);
        src_mac.copy_from_slice(&frame[ETH_ALEN..ETH_ALEN * 2]);

        // Learn source MAC.
        // Ignore learn errors (e.g., FDB full with all static entries).
        let _ = self.learn(&src_mac, ingress_port);

        // Check if destination is broadcast or multicast.
        let is_broadcast = dst_mac == [0xFF; ETH_ALEN];
        let is_multicast = (dst_mac[0] & 0x01) != 0;

        if is_broadcast || is_multicast {
            return Ok(self.flood_ports(ingress_port, ports_out));
        }

        // Unicast lookup.
        if let Some(dst_port) = self.lookup(&dst_mac) {
            if dst_port == ingress_port {
                // Destination is on the same port — no forwarding needed.
                return Ok(0);
            }
            // Verify destination port can forward.
            if let Ok(p) = self.find_port(dst_port) {
                if p.state.can_forward() {
                    ports_out[0] = dst_port;
                    return Ok(1);
                }
            }
            // Port exists but not forwarding — flood.
            return Ok(self.flood_ports(ingress_port, ports_out));
        }

        // Unknown unicast — flood.
        Ok(self.flood_ports(ingress_port, ports_out))
    }

    /// Advance the FDB ageing timer by one tick.
    ///
    /// Decrements the ageing timer of all dynamic FDB entries and
    /// removes those that reach zero.  Returns the number of entries
    /// aged out.
    pub fn tick(&mut self) -> u32 {
        self.tick_counter = self.tick_counter.wrapping_add(1);
        let mut aged = 0u32;
        for i in 0..MAX_FDB_ENTRIES {
            if self.fdb[i].in_use && !self.fdb[i].is_static {
                if self.fdb[i].aging_timer > 0 {
                    self.fdb[i].aging_timer -= 1;
                }
                if self.fdb[i].aging_timer == 0 {
                    self.fdb[i].in_use = false;
                    aged += 1;
                }
            }
        }
        aged
    }

    /// Return the number of active ports.
    pub fn port_count(&self) -> usize {
        let mut count = 0;
        for i in 0..MAX_PORTS {
            if self.ports[i].in_use {
                count += 1;
            }
        }
        count
    }

    /// Return the number of active FDB entries.
    pub fn fdb_count(&self) -> usize {
        let mut count = 0;
        for i in 0..MAX_FDB_ENTRIES {
            if self.fdb[i].in_use {
                count += 1;
            }
        }
        count
    }

    // -- private helpers --

    /// Find a port by ID, returning a reference.
    fn find_port(&self, port_id: u8) -> Result<&BridgePort> {
        for i in 0..MAX_PORTS {
            if self.ports[i].in_use && self.ports[i].port_id == port_id {
                return Ok(&self.ports[i]);
            }
        }
        Err(Error::NotFound)
    }

    /// Collect all forwarding ports except `except_port` into
    /// `ports_out`.  Returns the number of ports collected.
    fn flood_ports(&self, except_port: u8, ports_out: &mut [u8; MAX_PORTS]) -> usize {
        let mut count = 0;
        for i in 0..MAX_PORTS {
            if self.ports[i].in_use
                && self.ports[i].port_id != except_port
                && self.ports[i].state.can_forward()
                && count < MAX_PORTS
            {
                ports_out[count] = self.ports[i].port_id;
                count += 1;
            }
        }
        count
    }
}

// =========================================================================
// BridgeRegistry
// =========================================================================

/// System-wide registry of network bridges.
///
/// Manages up to [`MAX_BRIDGES`] bridge instances.  Each bridge is
/// identified by a monotonically increasing ID.
pub struct BridgeRegistry {
    /// Bridge slots.
    bridges: [BridgeDevice; MAX_BRIDGES],
    /// Next bridge ID to assign.
    next_id: u32,
}

impl Default for BridgeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BridgeRegistry {
    /// Create an empty bridge registry.
    pub const fn new() -> Self {
        Self {
            bridges: [BridgeDevice::EMPTY; MAX_BRIDGES],
            next_id: 1,
        }
    }

    /// Create a new bridge.
    ///
    /// Returns the bridge ID on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn create(&mut self) -> Result<u32> {
        for i in 0..MAX_BRIDGES {
            if !self.bridges[i].in_use {
                let id = self.next_id;
                self.next_id = self.next_id.wrapping_add(1);
                self.bridges[i] = BridgeDevice::new(id);
                self.bridges[i].in_use = true;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Destroy a bridge by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the bridge does not exist.
    pub fn destroy(&mut self, bridge_id: u32) -> Result<()> {
        for i in 0..MAX_BRIDGES {
            if self.bridges[i].in_use && self.bridges[i].bridge_id == bridge_id {
                self.bridges[i].in_use = false;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Look up a bridge by ID, returning a mutable reference.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the bridge does not exist.
    pub fn find(&mut self, bridge_id: u32) -> Result<&mut BridgeDevice> {
        for i in 0..MAX_BRIDGES {
            if self.bridges[i].in_use && self.bridges[i].bridge_id == bridge_id {
                return Ok(&mut self.bridges[i]);
            }
        }
        Err(Error::NotFound)
    }

    /// Add a port to a bridge.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the bridge does not exist.
    /// - [`Error::OutOfMemory`] if the bridge has no free port slots.
    /// - [`Error::AlreadyExists`] if the port ID is already in use.
    pub fn add_port(
        &mut self,
        bridge_id: u32,
        port_id: u8,
        mac_addr: [u8; ETH_ALEN],
    ) -> Result<()> {
        let bridge = self.find(bridge_id)?;
        bridge.add_port(port_id, mac_addr)
    }

    /// Remove a port from a bridge.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the bridge or port does not exist.
    pub fn remove_port(&mut self, bridge_id: u32, port_id: u8) -> Result<()> {
        let bridge = self.find(bridge_id)?;
        bridge.remove_port(port_id)
    }

    /// Forward a frame through a bridge.
    ///
    /// Performs source MAC learning and destination MAC lookup on the
    /// specified bridge.  Returns the list of destination port IDs.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the bridge does not exist.
    /// - [`Error::InvalidArgument`] if the frame is invalid or the
    ///   ingress port is not forwarding.
    pub fn forward_frame(
        &mut self,
        bridge_id: u32,
        frame: &[u8],
        ingress_port: u8,
        ports_out: &mut [u8; MAX_PORTS],
    ) -> Result<usize> {
        let bridge = self.find(bridge_id)?;
        bridge.forward(frame, ingress_port, ports_out)
    }

    /// Tick all active bridges (FDB ageing).
    ///
    /// Returns the total number of FDB entries aged out across all
    /// bridges.
    pub fn tick(&mut self) -> u32 {
        let mut total_aged = 0u32;
        for i in 0..MAX_BRIDGES {
            if self.bridges[i].in_use {
                total_aged += self.bridges[i].tick();
            }
        }
        total_aged
    }

    /// Return the number of active bridges.
    pub fn active_count(&self) -> usize {
        let mut count = 0;
        for i in 0..MAX_BRIDGES {
            if self.bridges[i].in_use {
                count += 1;
            }
        }
        count
    }
}
