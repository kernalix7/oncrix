// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IPv4 routing table and network interface management.
//!
//! Provides a longest-prefix-match routing table with up to
//! [`ROUTE_TABLE_SIZE`] entries, a network interface table with up
//! to [`IFACE_TABLE_SIZE`] interfaces, and route lookup that returns
//! a [`RouteAction`] indicating how a packet should be forwarded.
//!
//! All structures are fixed-size and allocation-free, suitable for
//! use in a `#![no_std]` kernel environment.

use oncrix_lib::{Error, Result};

// =========================================================================
// Ipv4Addr
// =========================================================================

/// A wrapper around a four-byte IPv4 address.
///
/// Stores the address in network byte order (big-endian) as four
/// individual octets, matching the on-wire representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Ipv4Addr {
    /// The four octets of the IPv4 address.
    octets: [u8; 4],
}

impl Ipv4Addr {
    /// The all-zeros address (`0.0.0.0`).
    pub const UNSPECIFIED: Self = Self {
        octets: [0, 0, 0, 0],
    };

    /// The loopback address (`127.0.0.1`).
    pub const LOOPBACK: Self = Self {
        octets: [127, 0, 0, 1],
    };

    /// The broadcast address (`255.255.255.255`).
    pub const BROADCAST: Self = Self {
        octets: [255, 255, 255, 255],
    };

    /// Create an [`Ipv4Addr`] from four individual octets.
    pub const fn from_octets(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self {
            octets: [a, b, c, d],
        }
    }

    /// Create an [`Ipv4Addr`] from a byte array.
    pub const fn from_bytes(bytes: [u8; 4]) -> Self {
        Self { octets: bytes }
    }

    /// Return the four octets as a byte array.
    pub const fn octets(&self) -> [u8; 4] {
        self.octets
    }

    /// Convert the address to a 32-bit integer in host byte order.
    ///
    /// The first octet occupies the most significant byte.
    pub const fn to_u32(&self) -> u32 {
        ((self.octets[0] as u32) << 24)
            | ((self.octets[1] as u32) << 16)
            | ((self.octets[2] as u32) << 8)
            | (self.octets[3] as u32)
    }

    /// Create an [`Ipv4Addr`] from a 32-bit integer in host byte
    /// order.
    pub const fn from_u32(val: u32) -> Self {
        Self {
            octets: [
                (val >> 24) as u8,
                (val >> 16) as u8,
                (val >> 8) as u8,
                val as u8,
            ],
        }
    }

    /// Returns `true` if this is the unspecified address (`0.0.0.0`).
    pub const fn is_unspecified(&self) -> bool {
        self.octets[0] == 0 && self.octets[1] == 0 && self.octets[2] == 0 && self.octets[3] == 0
    }

    /// Returns `true` if this is a loopback address (`127.x.x.x`).
    pub const fn is_loopback(&self) -> bool {
        self.octets[0] == 127
    }

    /// Format the address into a fixed-size buffer as
    /// `"a.b.c.d"`.
    ///
    /// Returns the number of bytes written to `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `buf` is shorter than
    /// 15 bytes (the maximum formatted length of an IPv4 address).
    pub fn format(&self, buf: &mut [u8]) -> Result<usize> {
        // Maximum length: "255.255.255.255" = 15 chars.
        if buf.len() < 15 {
            return Err(Error::InvalidArgument);
        }
        let mut pos: usize = 0;
        let mut i: usize = 0;
        while i < 4 {
            if i > 0 {
                buf[pos] = b'.';
                pos = pos.saturating_add(1);
            }
            pos = pos.saturating_add(format_u8(self.octets[i], &mut buf[pos..]));
            i = i.saturating_add(1);
        }
        Ok(pos)
    }
}

impl Default for Ipv4Addr {
    fn default() -> Self {
        Self::UNSPECIFIED
    }
}

/// Format a `u8` value as decimal ASCII into `buf`.
///
/// Returns the number of bytes written (1 to 3).
fn format_u8(val: u8, buf: &mut [u8]) -> usize {
    if val >= 100 {
        buf[0] = b'0' + (val / 100);
        buf[1] = b'0' + ((val / 10) % 10);
        buf[2] = b'0' + (val % 10);
        3
    } else if val >= 10 {
        buf[0] = b'0' + (val / 10);
        buf[1] = b'0' + (val % 10);
        2
    } else {
        buf[0] = b'0' + val;
        1
    }
}

// =========================================================================
// RouteFlags
// =========================================================================

/// Bitmask flags for a routing table entry.
///
/// Modelled after the traditional `RTF_*` flags from the BSD/Linux
/// routing subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteFlags(u32);

impl RouteFlags {
    /// Route is active and usable.
    pub const UP: Self = Self(1 << 0);

    /// Destination is reached via a gateway.
    pub const GATEWAY: Self = Self(1 << 1);

    /// Destination is a single host (not a network).
    pub const HOST: Self = Self(1 << 2);

    /// Reject packets matching this route.
    pub const REJECT: Self = Self(1 << 3);

    /// Route was created dynamically (e.g., by ICMP redirect).
    pub const DYNAMIC: Self = Self(1 << 4);

    /// Empty flag set.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Returns `true` if the flag set contains `other`.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Return the union of `self` and `other`.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Return the raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Create from raw bits.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }
}

impl Default for RouteFlags {
    fn default() -> Self {
        Self::empty()
    }
}

// =========================================================================
// RouteEntry
// =========================================================================

/// A single entry in the routing table.
///
/// Represents a route to a destination network (identified by
/// `destination` and `netmask`) via an optional `gateway`, reachable
/// through the interface identified by `iface_index`.
#[derive(Debug, Clone, Copy)]
pub struct RouteEntry {
    /// Destination network address.
    pub destination: Ipv4Addr,
    /// Network mask determining the prefix length.
    pub netmask: Ipv4Addr,
    /// Gateway address (zero if directly connected).
    pub gateway: Ipv4Addr,
    /// Index of the outgoing network interface.
    pub iface_index: u32,
    /// Route metric (lower is preferred).
    pub metric: u32,
    /// Route flags.
    pub flags: RouteFlags,
    /// Whether this slot is occupied.
    valid: bool,
}

impl RouteEntry {
    /// Create an empty, invalid route entry.
    const fn empty() -> Self {
        Self {
            destination: Ipv4Addr::UNSPECIFIED,
            netmask: Ipv4Addr::UNSPECIFIED,
            gateway: Ipv4Addr::UNSPECIFIED,
            iface_index: 0,
            metric: 0,
            flags: RouteFlags::empty(),
            valid: false,
        }
    }

    /// Return the prefix length (number of leading 1-bits in the
    /// netmask).
    pub const fn prefix_len(&self) -> u32 {
        let mask = self.netmask.to_u32();
        if mask == 0 {
            return 0;
        }
        // Count leading ones by counting leading zeros of the
        // bitwise complement.
        (!mask).leading_zeros()
    }

    /// Returns `true` if `addr` matches this route's destination
    /// network after applying the netmask.
    pub const fn matches(&self, addr: Ipv4Addr) -> bool {
        let mask = self.netmask.to_u32();
        (addr.to_u32() & mask) == (self.destination.to_u32() & mask)
    }
}

impl Default for RouteEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// =========================================================================
// RoutingTable
// =========================================================================

/// Maximum number of entries in the routing table.
const ROUTE_TABLE_SIZE: usize = 64;

/// IPv4 routing table with longest-prefix-match lookup.
///
/// Holds up to [`ROUTE_TABLE_SIZE`] (64) route entries.  Routes are
/// matched using longest-prefix-match with metric as a tiebreaker
/// (lower metric wins).
pub struct RoutingTable {
    /// Fixed-size array of route entries.
    entries: [RouteEntry; ROUTE_TABLE_SIZE],
}

impl Default for RoutingTable {
    fn default() -> Self {
        Self::new()
    }
}

impl RoutingTable {
    /// Create an empty routing table.
    pub const fn new() -> Self {
        Self {
            entries: [RouteEntry::empty(); ROUTE_TABLE_SIZE],
        }
    }

    /// Add a new route to the table.
    ///
    /// If a route with the same destination, netmask, and gateway
    /// already exists, it is updated in place.  Otherwise the first
    /// free slot is used.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn add(
        &mut self,
        destination: Ipv4Addr,
        netmask: Ipv4Addr,
        gateway: Ipv4Addr,
        iface_index: u32,
        metric: u32,
        flags: RouteFlags,
    ) -> Result<()> {
        // Check for existing matching entry.
        for entry in &mut self.entries {
            if entry.valid
                && entry.destination == destination
                && entry.netmask == netmask
                && entry.gateway == gateway
            {
                entry.iface_index = iface_index;
                entry.metric = metric;
                entry.flags = flags;
                return Ok(());
            }
        }

        // Find first free slot.
        for entry in &mut self.entries {
            if !entry.valid {
                entry.destination = destination;
                entry.netmask = netmask;
                entry.gateway = gateway;
                entry.iface_index = iface_index;
                entry.metric = metric;
                entry.flags = flags;
                entry.valid = true;
                return Ok(());
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Delete a route matching the given destination, netmask, and
    /// gateway.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching route exists.
    pub fn delete(
        &mut self,
        destination: Ipv4Addr,
        netmask: Ipv4Addr,
        gateway: Ipv4Addr,
    ) -> Result<()> {
        for entry in &mut self.entries {
            if entry.valid
                && entry.destination == destination
                && entry.netmask == netmask
                && entry.gateway == gateway
            {
                entry.valid = false;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Replace an existing route or insert a new one.
    ///
    /// If a route with the same destination and netmask exists
    /// (regardless of gateway), it is replaced.  Otherwise a new
    /// entry is added.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if no matching entry exists
    /// and the table is full.
    pub fn replace(
        &mut self,
        destination: Ipv4Addr,
        netmask: Ipv4Addr,
        gateway: Ipv4Addr,
        iface_index: u32,
        metric: u32,
        flags: RouteFlags,
    ) -> Result<()> {
        // Try to replace an existing entry with the same
        // destination/netmask.
        for entry in &mut self.entries {
            if entry.valid && entry.destination == destination && entry.netmask == netmask {
                entry.gateway = gateway;
                entry.iface_index = iface_index;
                entry.metric = metric;
                entry.flags = flags;
                return Ok(());
            }
        }

        // No existing entry — add a new one.
        self.add(destination, netmask, gateway, iface_index, metric, flags)
    }

    /// Perform a longest-prefix-match lookup for `dest`.
    ///
    /// Returns the best matching [`RouteEntry`] — the one with the
    /// longest prefix that matches `dest`.  If multiple routes share
    /// the same prefix length, the one with the lowest metric wins.
    /// Only routes with [`RouteFlags::UP`] set are considered.
    ///
    /// Returns `None` if no matching route is found.
    pub fn lookup(&self, dest: Ipv4Addr) -> Option<&RouteEntry> {
        let mut best: Option<&RouteEntry> = None;
        let mut best_prefix: u32 = 0;
        let mut best_metric: u32 = u32::MAX;

        for entry in &self.entries {
            if !entry.valid {
                continue;
            }
            if !entry.flags.contains(RouteFlags::UP) {
                continue;
            }
            if entry.flags.contains(RouteFlags::REJECT) {
                // Reject routes are still eligible for matching —
                // the caller checks the flags.
            }
            if !entry.matches(dest) {
                continue;
            }

            let prefix = entry.prefix_len();
            if prefix > best_prefix || (prefix == best_prefix && entry.metric < best_metric) {
                best = Some(entry);
                best_prefix = prefix;
                best_metric = entry.metric;
            }
        }

        best
    }

    /// Return the number of valid (occupied) entries.
    pub fn count(&self) -> usize {
        let mut n: usize = 0;
        for entry in &self.entries {
            if entry.valid {
                n = n.saturating_add(1);
            }
        }
        n
    }
}

// =========================================================================
// InterfaceFlags
// =========================================================================

/// Bitmask flags for a network interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceFlags(u32);

impl InterfaceFlags {
    /// Interface is administratively up.
    pub const UP: Self = Self(1 << 0);

    /// Interface has a valid link / carrier.
    pub const RUNNING: Self = Self(1 << 1);

    /// Interface is a loopback device.
    pub const LOOPBACK: Self = Self(1 << 2);

    /// Empty flag set.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Returns `true` if the flag set contains `other`.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Return the union of `self` and `other`.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Return the raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Create from raw bits.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }
}

impl Default for InterfaceFlags {
    fn default() -> Self {
        Self::empty()
    }
}

// =========================================================================
// InterfaceInfo
// =========================================================================

/// Description of a single network interface.
#[derive(Debug, Clone, Copy)]
pub struct InterfaceInfo {
    /// Interface index (unique identifier).
    pub index: u32,
    /// Interface name (e.g., `b"eth0"`, NUL-padded).
    pub name: [u8; 16],
    /// IPv4 address assigned to this interface.
    pub addr: Ipv4Addr,
    /// Subnet mask.
    pub netmask: Ipv4Addr,
    /// Maximum transmission unit in bytes.
    pub mtu: u32,
    /// Interface flags.
    pub flags: InterfaceFlags,
    /// Whether this slot is occupied.
    valid: bool,
}

impl InterfaceInfo {
    /// Create an empty, invalid interface entry.
    const fn empty() -> Self {
        Self {
            index: 0,
            name: [0u8; 16],
            addr: Ipv4Addr::UNSPECIFIED,
            netmask: Ipv4Addr::UNSPECIFIED,
            mtu: 0,
            flags: InterfaceFlags::empty(),
            valid: false,
        }
    }

    /// Return the interface name as a byte slice (without trailing
    /// NUL padding).
    pub fn name_str(&self) -> &[u8] {
        let mut len = 0;
        while len < self.name.len() && self.name[len] != 0 {
            len = len.saturating_add(1);
        }
        &self.name[..len]
    }
}

impl Default for InterfaceInfo {
    fn default() -> Self {
        Self::empty()
    }
}

// =========================================================================
// InterfaceTable
// =========================================================================

/// Maximum number of network interfaces.
const IFACE_TABLE_SIZE: usize = 8;

/// Table of registered network interfaces.
///
/// Holds up to [`IFACE_TABLE_SIZE`] (8) interfaces, each identified
/// by a unique index.
pub struct InterfaceTable {
    /// Fixed-size array of interface entries.
    entries: [InterfaceInfo; IFACE_TABLE_SIZE],
}

impl Default for InterfaceTable {
    fn default() -> Self {
        Self::new()
    }
}

impl InterfaceTable {
    /// Create an empty interface table.
    pub const fn new() -> Self {
        Self {
            entries: [InterfaceInfo::empty(); IFACE_TABLE_SIZE],
        }
    }

    /// Register a new network interface.
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyExists`] if an interface with the same
    ///   `index` is already registered.
    /// - [`Error::OutOfMemory`] if the table is full.
    /// - [`Error::InvalidArgument`] if `name` is empty or longer
    ///   than 16 bytes.
    pub fn register(
        &mut self,
        index: u32,
        name: &[u8],
        addr: Ipv4Addr,
        netmask: Ipv4Addr,
        mtu: u32,
        flags: InterfaceFlags,
    ) -> Result<()> {
        if name.is_empty() || name.len() > 16 {
            return Err(Error::InvalidArgument);
        }

        // Check for duplicate index.
        for entry in &self.entries {
            if entry.valid && entry.index == index {
                return Err(Error::AlreadyExists);
            }
        }

        // Find first free slot.
        for entry in &mut self.entries {
            if !entry.valid {
                entry.index = index;
                entry.name = [0u8; 16];
                entry.name[..name.len()].copy_from_slice(name);
                entry.addr = addr;
                entry.netmask = netmask;
                entry.mtu = mtu;
                entry.flags = flags;
                entry.valid = true;
                return Ok(());
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Unregister the interface with the given `index`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no interface with the given
    /// index exists.
    pub fn unregister(&mut self, index: u32) -> Result<()> {
        for entry in &mut self.entries {
            if entry.valid && entry.index == index {
                entry.valid = false;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Look up an interface by its index.
    ///
    /// Returns `None` if no registered interface has the given index.
    pub fn get(&self, index: u32) -> Option<&InterfaceInfo> {
        self.entries
            .iter()
            .find(|entry| entry.valid && entry.index == index)
    }

    /// Look up an interface by name.
    ///
    /// Returns `None` if no registered interface has a matching name.
    pub fn get_by_name(&self, name: &[u8]) -> Option<&InterfaceInfo> {
        self.entries
            .iter()
            .find(|entry| entry.valid && entry.name_str() == name)
    }

    /// Return the number of registered interfaces.
    pub fn count(&self) -> usize {
        let mut n: usize = 0;
        for entry in &self.entries {
            if entry.valid {
                n = n.saturating_add(1);
            }
        }
        n
    }
}

// =========================================================================
// RouteAction
// =========================================================================

/// The result of a route lookup, indicating how a packet should be
/// handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteAction {
    /// Forward the packet to `gateway` via interface `iface_index`.
    Forward {
        /// Next-hop gateway address.
        gateway: Ipv4Addr,
        /// Outgoing interface index.
        iface_index: u32,
    },
    /// Deliver the packet locally via interface `iface_index`.
    Deliver {
        /// Interface index on which the packet arrived or should
        /// be delivered.
        iface_index: u32,
    },
    /// Reject the packet (send ICMP unreachable to sender).
    Reject,
    /// No route to destination.
    Unreachable,
}

// =========================================================================
// route_lookup
// =========================================================================

/// Perform a route lookup and return a [`RouteAction`].
///
/// Consults the `routing_table` for the best matching route to
/// `dest`.  If the matched route has the [`RouteFlags::GATEWAY`]
/// flag set, a [`RouteAction::Forward`] is returned; otherwise a
/// [`RouteAction::Deliver`] is returned for directly-connected
/// networks.  Routes with [`RouteFlags::REJECT`] produce
/// [`RouteAction::Reject`].
///
/// Returns [`RouteAction::Unreachable`] if no route matches.
pub fn route_lookup(routing_table: &RoutingTable, dest: Ipv4Addr) -> RouteAction {
    match routing_table.lookup(dest) {
        Some(entry) => {
            if entry.flags.contains(RouteFlags::REJECT) {
                RouteAction::Reject
            } else if entry.flags.contains(RouteFlags::GATEWAY) {
                RouteAction::Forward {
                    gateway: entry.gateway,
                    iface_index: entry.iface_index,
                }
            } else {
                RouteAction::Deliver {
                    iface_index: entry.iface_index,
                }
            }
        }
        None => RouteAction::Unreachable,
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Ipv4Addr ---------------------------------------------------------

    #[test]
    fn test_ipv4_addr_from_octets() {
        let addr = Ipv4Addr::from_octets(192, 168, 1, 1);
        assert_eq!(addr.octets(), [192, 168, 1, 1]);
    }

    #[test]
    fn test_ipv4_addr_to_u32_roundtrip() {
        let addr = Ipv4Addr::from_octets(10, 0, 0, 1);
        let val = addr.to_u32();
        assert_eq!(val, 0x0A00_0001);
        assert_eq!(Ipv4Addr::from_u32(val), addr);
    }

    #[test]
    fn test_ipv4_addr_format() {
        let addr = Ipv4Addr::from_octets(192, 168, 1, 100);
        let mut buf = [0u8; 16];
        let len = addr.format(&mut buf).ok().unwrap_or(0);
        assert_eq!(&buf[..len], b"192.168.1.100");
    }

    #[test]
    fn test_ipv4_addr_format_zeros() {
        let addr = Ipv4Addr::UNSPECIFIED;
        let mut buf = [0u8; 16];
        let len = addr.format(&mut buf).ok().unwrap_or(0);
        assert_eq!(&buf[..len], b"0.0.0.0");
    }

    #[test]
    fn test_ipv4_addr_format_max() {
        let addr = Ipv4Addr::BROADCAST;
        let mut buf = [0u8; 16];
        let len = addr.format(&mut buf).ok().unwrap_or(0);
        assert_eq!(&buf[..len], b"255.255.255.255");
    }

    #[test]
    fn test_ipv4_addr_is_loopback() {
        assert!(Ipv4Addr::LOOPBACK.is_loopback());
        assert!(Ipv4Addr::from_octets(127, 0, 0, 2).is_loopback());
        assert!(!Ipv4Addr::from_octets(10, 0, 0, 1).is_loopback());
    }

    #[test]
    fn test_ipv4_addr_default() {
        let addr = Ipv4Addr::default();
        assert!(addr.is_unspecified());
    }

    // -- RouteFlags -------------------------------------------------------

    #[test]
    fn test_route_flags_contains() {
        let flags = RouteFlags::UP.union(RouteFlags::GATEWAY);
        assert!(flags.contains(RouteFlags::UP));
        assert!(flags.contains(RouteFlags::GATEWAY));
        assert!(!flags.contains(RouteFlags::HOST));
    }

    #[test]
    fn test_route_flags_bits_roundtrip() {
        let flags = RouteFlags::UP.union(RouteFlags::DYNAMIC);
        let bits = flags.bits();
        assert_eq!(RouteFlags::from_bits(bits), flags);
    }

    // -- RouteEntry -------------------------------------------------------

    #[test]
    fn test_route_entry_prefix_len() {
        let mut entry = RouteEntry::empty();
        entry.netmask = Ipv4Addr::from_octets(255, 255, 255, 0);
        assert_eq!(entry.prefix_len(), 24);

        entry.netmask = Ipv4Addr::from_octets(255, 255, 0, 0);
        assert_eq!(entry.prefix_len(), 16);

        entry.netmask = Ipv4Addr::UNSPECIFIED;
        assert_eq!(entry.prefix_len(), 0);
    }

    #[test]
    fn test_route_entry_matches() {
        let mut entry = RouteEntry::empty();
        entry.destination = Ipv4Addr::from_octets(192, 168, 1, 0);
        entry.netmask = Ipv4Addr::from_octets(255, 255, 255, 0);

        assert!(entry.matches(Ipv4Addr::from_octets(192, 168, 1, 42)));
        assert!(entry.matches(Ipv4Addr::from_octets(192, 168, 1, 255)));
        assert!(!entry.matches(Ipv4Addr::from_octets(192, 168, 2, 1)));
    }

    // -- RoutingTable -----------------------------------------------------

    #[test]
    fn test_routing_table_add_and_lookup() {
        let mut table = RoutingTable::new();
        let flags = RouteFlags::UP;

        table
            .add(
                Ipv4Addr::from_octets(192, 168, 1, 0),
                Ipv4Addr::from_octets(255, 255, 255, 0),
                Ipv4Addr::UNSPECIFIED,
                1,
                10,
                flags,
            )
            .ok();

        let entry = table.lookup(Ipv4Addr::from_octets(192, 168, 1, 42));
        assert!(entry.is_some());
        let entry = entry.unwrap_or(&RouteEntry::empty());
        assert_eq!(entry.iface_index, 1);
    }

    #[test]
    fn test_routing_table_longest_prefix_match() {
        let mut table = RoutingTable::new();
        let up = RouteFlags::UP;

        // Default route: 0.0.0.0/0 via gateway.
        table
            .add(
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::from_octets(10, 0, 0, 1),
                0,
                100,
                up.union(RouteFlags::GATEWAY),
            )
            .ok();

        // /24 route for 10.0.0.0/24.
        table
            .add(
                Ipv4Addr::from_octets(10, 0, 0, 0),
                Ipv4Addr::from_octets(255, 255, 255, 0),
                Ipv4Addr::UNSPECIFIED,
                1,
                10,
                up,
            )
            .ok();

        // Lookup within /24 should match the more specific route.
        let entry = table.lookup(Ipv4Addr::from_octets(10, 0, 0, 50));
        assert!(entry.is_some());
        let entry = entry.unwrap_or(&RouteEntry::empty());
        assert_eq!(entry.iface_index, 1);
        assert_eq!(entry.metric, 10);

        // Lookup outside /24 should match the default route.
        let entry = table.lookup(Ipv4Addr::from_octets(8, 8, 8, 8));
        assert!(entry.is_some());
        let entry = entry.unwrap_or(&RouteEntry::empty());
        assert_eq!(entry.iface_index, 0);
        assert_eq!(entry.metric, 100);
    }

    #[test]
    fn test_routing_table_metric_tiebreak() {
        let mut table = RoutingTable::new();
        let up = RouteFlags::UP;

        // Two routes to the same prefix with different metrics.
        table
            .add(
                Ipv4Addr::from_octets(10, 0, 0, 0),
                Ipv4Addr::from_octets(255, 255, 255, 0),
                Ipv4Addr::UNSPECIFIED,
                1,
                200,
                up,
            )
            .ok();
        table
            .add(
                Ipv4Addr::from_octets(10, 0, 0, 0),
                Ipv4Addr::from_octets(255, 255, 255, 0),
                Ipv4Addr::from_octets(10, 0, 0, 1),
                2,
                50,
                up.union(RouteFlags::GATEWAY),
            )
            .ok();

        let entry = table.lookup(Ipv4Addr::from_octets(10, 0, 0, 99));
        assert!(entry.is_some());
        let entry = entry.unwrap_or(&RouteEntry::empty());
        // Should prefer the lower metric (50) route.
        assert_eq!(entry.iface_index, 2);
        assert_eq!(entry.metric, 50);
    }

    #[test]
    fn test_routing_table_delete() {
        let mut table = RoutingTable::new();
        let up = RouteFlags::UP;

        table
            .add(
                Ipv4Addr::from_octets(10, 0, 0, 0),
                Ipv4Addr::from_octets(255, 255, 255, 0),
                Ipv4Addr::UNSPECIFIED,
                1,
                10,
                up,
            )
            .ok();

        assert_eq!(table.count(), 1);

        table
            .delete(
                Ipv4Addr::from_octets(10, 0, 0, 0),
                Ipv4Addr::from_octets(255, 255, 255, 0),
                Ipv4Addr::UNSPECIFIED,
            )
            .ok();

        assert_eq!(table.count(), 0);
        assert!(table.lookup(Ipv4Addr::from_octets(10, 0, 0, 1)).is_none());
    }

    #[test]
    fn test_routing_table_delete_not_found() {
        let mut table = RoutingTable::new();
        let result = table.delete(
            Ipv4Addr::from_octets(10, 0, 0, 0),
            Ipv4Addr::from_octets(255, 255, 255, 0),
            Ipv4Addr::UNSPECIFIED,
        );
        assert_eq!(result, Err(Error::NotFound));
    }

    #[test]
    fn test_routing_table_replace() {
        let mut table = RoutingTable::new();
        let up = RouteFlags::UP;

        table
            .add(
                Ipv4Addr::from_octets(10, 0, 0, 0),
                Ipv4Addr::from_octets(255, 255, 255, 0),
                Ipv4Addr::UNSPECIFIED,
                1,
                100,
                up,
            )
            .ok();

        // Replace with a different gateway and metric.
        table
            .replace(
                Ipv4Addr::from_octets(10, 0, 0, 0),
                Ipv4Addr::from_octets(255, 255, 255, 0),
                Ipv4Addr::from_octets(10, 0, 0, 254),
                2,
                50,
                up.union(RouteFlags::GATEWAY),
            )
            .ok();

        // Should still be one entry.
        assert_eq!(table.count(), 1);

        let entry = table.lookup(Ipv4Addr::from_octets(10, 0, 0, 1));
        assert!(entry.is_some());
        let entry = entry.unwrap_or(&RouteEntry::empty());
        assert_eq!(entry.gateway, Ipv4Addr::from_octets(10, 0, 0, 254));
        assert_eq!(entry.iface_index, 2);
        assert_eq!(entry.metric, 50);
    }

    #[test]
    fn test_routing_table_full() {
        let mut table = RoutingTable::new();
        let up = RouteFlags::UP;

        // Fill all 64 slots.
        for i in 0..ROUTE_TABLE_SIZE {
            let result = table.add(
                Ipv4Addr::from_octets(10, 0, (i / 256) as u8, (i % 256) as u8),
                Ipv4Addr::from_octets(255, 255, 255, 255),
                Ipv4Addr::UNSPECIFIED,
                1,
                10,
                up,
            );
            assert!(result.is_ok());
        }

        // 65th entry should fail.
        let result = table.add(
            Ipv4Addr::from_octets(172, 16, 0, 0),
            Ipv4Addr::from_octets(255, 255, 0, 0),
            Ipv4Addr::UNSPECIFIED,
            2,
            10,
            up,
        );
        assert_eq!(result, Err(Error::OutOfMemory));
    }

    // -- InterfaceTable ---------------------------------------------------

    #[test]
    fn test_interface_register_and_get() {
        let mut table = InterfaceTable::new();
        let flags = InterfaceFlags::UP.union(InterfaceFlags::RUNNING);

        table
            .register(
                1,
                b"eth0",
                Ipv4Addr::from_octets(192, 168, 1, 10),
                Ipv4Addr::from_octets(255, 255, 255, 0),
                1500,
                flags,
            )
            .ok();

        let iface = table.get(1);
        assert!(iface.is_some());
        let iface = iface.unwrap_or(&InterfaceInfo::empty());
        assert_eq!(iface.name_str(), b"eth0");
        assert_eq!(iface.mtu, 1500);
        assert!(iface.flags.contains(InterfaceFlags::UP));
    }

    #[test]
    fn test_interface_get_by_name() {
        let mut table = InterfaceTable::new();
        let flags = InterfaceFlags::UP
            .union(InterfaceFlags::RUNNING)
            .union(InterfaceFlags::LOOPBACK);

        table
            .register(
                0,
                b"lo",
                Ipv4Addr::LOOPBACK,
                Ipv4Addr::from_octets(255, 0, 0, 0),
                65536,
                flags,
            )
            .ok();

        let iface = table.get_by_name(b"lo");
        assert!(iface.is_some());
        let iface = iface.unwrap_or(&InterfaceInfo::empty());
        assert_eq!(iface.index, 0);
        assert!(iface.flags.contains(InterfaceFlags::LOOPBACK));
    }

    #[test]
    fn test_interface_unregister() {
        let mut table = InterfaceTable::new();
        table
            .register(
                1,
                b"eth0",
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::UNSPECIFIED,
                1500,
                InterfaceFlags::empty(),
            )
            .ok();

        assert_eq!(table.count(), 1);
        table.unregister(1).ok();
        assert_eq!(table.count(), 0);
        assert!(table.get(1).is_none());
    }

    #[test]
    fn test_interface_duplicate_index_rejected() {
        let mut table = InterfaceTable::new();
        table
            .register(
                1,
                b"eth0",
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::UNSPECIFIED,
                1500,
                InterfaceFlags::empty(),
            )
            .ok();

        let result = table.register(
            1,
            b"eth1",
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            1500,
            InterfaceFlags::empty(),
        );
        assert_eq!(result, Err(Error::AlreadyExists));
    }

    #[test]
    fn test_interface_table_full() {
        let mut table = InterfaceTable::new();
        for i in 0..IFACE_TABLE_SIZE {
            let mut name = [0u8; 4];
            name[0] = b'e';
            name[1] = b't';
            name[2] = b'h';
            name[3] = b'0' + i as u8;
            let result = table.register(
                i as u32,
                &name,
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::UNSPECIFIED,
                1500,
                InterfaceFlags::empty(),
            );
            assert!(result.is_ok());
        }

        let result = table.register(
            99,
            b"extra",
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            1500,
            InterfaceFlags::empty(),
        );
        assert_eq!(result, Err(Error::OutOfMemory));
    }

    // -- route_lookup -----------------------------------------------------

    #[test]
    fn test_route_lookup_forward() {
        let mut table = RoutingTable::new();
        let gw_flags = RouteFlags::UP.union(RouteFlags::GATEWAY);

        table
            .add(
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::from_octets(10, 0, 0, 1),
                0,
                100,
                gw_flags,
            )
            .ok();

        let action = route_lookup(&table, Ipv4Addr::from_octets(8, 8, 8, 8));
        assert_eq!(
            action,
            RouteAction::Forward {
                gateway: Ipv4Addr::from_octets(10, 0, 0, 1),
                iface_index: 0,
            }
        );
    }

    #[test]
    fn test_route_lookup_deliver() {
        let mut table = RoutingTable::new();
        table
            .add(
                Ipv4Addr::from_octets(192, 168, 1, 0),
                Ipv4Addr::from_octets(255, 255, 255, 0),
                Ipv4Addr::UNSPECIFIED,
                1,
                10,
                RouteFlags::UP,
            )
            .ok();

        let action = route_lookup(&table, Ipv4Addr::from_octets(192, 168, 1, 42));
        assert_eq!(action, RouteAction::Deliver { iface_index: 1 });
    }

    #[test]
    fn test_route_lookup_reject() {
        let mut table = RoutingTable::new();
        let flags = RouteFlags::UP.union(RouteFlags::REJECT);

        table
            .add(
                Ipv4Addr::from_octets(10, 0, 0, 0),
                Ipv4Addr::from_octets(255, 0, 0, 0),
                Ipv4Addr::UNSPECIFIED,
                0,
                10,
                flags,
            )
            .ok();

        let action = route_lookup(&table, Ipv4Addr::from_octets(10, 1, 2, 3));
        assert_eq!(action, RouteAction::Reject);
    }

    #[test]
    fn test_route_lookup_unreachable() {
        let table = RoutingTable::new();
        let action = route_lookup(&table, Ipv4Addr::from_octets(8, 8, 8, 8));
        assert_eq!(action, RouteAction::Unreachable);
    }

    #[test]
    fn test_route_lookup_ignores_down_routes() {
        let mut table = RoutingTable::new();
        // Route without UP flag should be ignored.
        table
            .add(
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::from_octets(10, 0, 0, 1),
                0,
                10,
                RouteFlags::GATEWAY,
            )
            .ok();

        let action = route_lookup(&table, Ipv4Addr::from_octets(8, 8, 8, 8));
        assert_eq!(action, RouteAction::Unreachable);
    }

    // -- Default impls verified -------------------------------------------

    #[test]
    fn test_defaults() {
        let _ = RoutingTable::default();
        let _ = InterfaceTable::default();
        let _ = RouteEntry::default();
        let _ = InterfaceInfo::default();
        let _ = RouteFlags::default();
        let _ = InterfaceFlags::default();
        let _ = Ipv4Addr::default();
    }
}
