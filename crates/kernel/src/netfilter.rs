// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Packet filter / firewall subsystem for the ONCRIX kernel.
//!
//! Provides a stateless packet filtering engine inspired by
//! netfilter/iptables, with three built-in chains (input, output,
//! forward), CIDR-based IP matching, port range matching,
//! per-rule packet/byte counters, and a basic NAT table for
//! SNAT/DNAT address translation.
//!
//! All structures are fixed-size and allocation-free, suitable for
//! use in a `#![no_std]` kernel environment.

use oncrix_lib::{Error, Result};

// =========================================================================
// Protocol
// =========================================================================

/// IP protocol selector for filter rules.
///
/// Matches against the protocol field in an IPv4 header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Protocol {
    /// Match any protocol.
    #[default]
    Any,
    /// Match TCP (protocol number 6).
    Tcp,
    /// Match UDP (protocol number 17).
    Udp,
    /// Match ICMP (protocol number 1).
    Icmp,
}

impl Protocol {
    /// Return the IP protocol number, or `None` for `Any`.
    pub const fn to_proto_num(self) -> Option<u8> {
        match self {
            Self::Any => None,
            Self::Tcp => Some(6),
            Self::Udp => Some(17),
            Self::Icmp => Some(1),
        }
    }

    /// Create a [`Protocol`] from an IP protocol number.
    ///
    /// Unknown protocol numbers map to `Any`.
    pub const fn from_proto_num(num: u8) -> Self {
        match num {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            _ => Self::Any,
        }
    }
}

// =========================================================================
// FilterAction
// =========================================================================

/// Action to take when a filter rule matches a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FilterAction {
    /// Allow the packet through.
    #[default]
    Accept,
    /// Silently discard the packet.
    Drop,
    /// Discard and send an ICMP error back to the source.
    Reject,
    /// Log the packet (and continue processing subsequent rules).
    Log,
}

// =========================================================================
// ChainType
// =========================================================================

/// Identifies which built-in chain a rule belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChainType {
    /// Packets destined for this host.
    #[default]
    Input,
    /// Packets originating from this host.
    Output,
    /// Packets being routed through this host.
    Forward,
}

// =========================================================================
// PacketDirection
// =========================================================================

/// Direction of a packet relative to this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PacketDirection {
    /// Incoming packet.
    #[default]
    Incoming,
    /// Outgoing packet.
    Outgoing,
}

// =========================================================================
// IpMask
// =========================================================================

/// An IPv4 address with a CIDR prefix length for subnet matching.
///
/// A prefix length of 0 matches any address.  A prefix length of
/// 32 matches a single host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpMask {
    /// IPv4 address stored as four octets in network byte order.
    pub addr: [u8; 4],
    /// CIDR prefix length (0..=32).
    pub prefix_len: u8,
}

impl IpMask {
    /// A wildcard mask that matches any address (`0.0.0.0/0`).
    pub const ANY: Self = Self {
        addr: [0, 0, 0, 0],
        prefix_len: 0,
    };

    /// Create a new [`IpMask`] from an address and prefix length.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `prefix_len` exceeds 32.
    pub const fn new(addr: [u8; 4], prefix_len: u8) -> Result<Self> {
        if prefix_len > 32 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { addr, prefix_len })
    }

    /// Check whether `target` falls within this masked network.
    pub const fn matches(&self, target: &[u8; 4]) -> bool {
        if self.prefix_len == 0 {
            return true;
        }
        let mask = if self.prefix_len >= 32 {
            0xFFFF_FFFFu32
        } else {
            0xFFFF_FFFFu32 << (32 - self.prefix_len)
        };
        let a = Self::to_u32(self.addr);
        let b = Self::to_u32(*target);
        (a & mask) == (b & mask)
    }

    /// Convert four octets to a host-order `u32`.
    const fn to_u32(octets: [u8; 4]) -> u32 {
        ((octets[0] as u32) << 24)
            | ((octets[1] as u32) << 16)
            | ((octets[2] as u32) << 8)
            | (octets[3] as u32)
    }
}

impl Default for IpMask {
    fn default() -> Self {
        Self::ANY
    }
}

// =========================================================================
// PortRange
// =========================================================================

/// A contiguous range of TCP/UDP port numbers.
///
/// Both `min` and `max` are inclusive.  A range of `0..=0` matches
/// any port (wildcard).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    /// Minimum port (inclusive).
    pub min: u16,
    /// Maximum port (inclusive).
    pub max: u16,
}

impl PortRange {
    /// A wildcard range matching any port.
    pub const ANY: Self = Self { min: 0, max: 0 };

    /// Create a new port range.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `min > max` (unless
    /// both are zero, which is the wildcard).
    pub const fn new(min: u16, max: u16) -> Result<Self> {
        if min > max {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { min, max })
    }

    /// Check whether `port` falls within this range.
    ///
    /// A wildcard range (`0..=0`) matches every port.
    pub const fn matches(&self, port: u16) -> bool {
        if self.min == 0 && self.max == 0 {
            return true;
        }
        port >= self.min && port <= self.max
    }
}

impl Default for PortRange {
    fn default() -> Self {
        Self::ANY
    }
}

// =========================================================================
// RuleStats
// =========================================================================

/// Per-rule packet and byte counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleStats {
    /// Number of packets that matched this rule.
    pub packets: u64,
    /// Total bytes of packets that matched this rule.
    pub bytes: u64,
}

impl RuleStats {
    /// Create zeroed counters.
    pub const fn new() -> Self {
        Self {
            packets: 0,
            bytes: 0,
        }
    }

    /// Record a match of `byte_count` bytes.
    pub fn record(&mut self, byte_count: u64) {
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(byte_count);
    }

    /// Reset counters to zero.
    pub fn reset(&mut self) {
        self.packets = 0;
        self.bytes = 0;
    }
}

impl Default for RuleStats {
    fn default() -> Self {
        Self::new()
    }
}

// =========================================================================
// PacketInfo
// =========================================================================

/// Extracted metadata from a packet for filter matching.
///
/// All fields use network byte order where applicable.  Ports are
/// zero for protocols that do not use ports (e.g., ICMP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketInfo {
    /// Source IPv4 address.
    pub src_ip: [u8; 4],
    /// Destination IPv4 address.
    pub dst_ip: [u8; 4],
    /// Source port (0 if not applicable).
    pub src_port: u16,
    /// Destination port (0 if not applicable).
    pub dst_port: u16,
    /// IP protocol.
    pub protocol: Protocol,
    /// Packet direction relative to this host.
    pub direction: PacketDirection,
    /// Interface index on which the packet was received or will
    /// be sent.
    pub iface_index: u32,
    /// Total packet length in bytes (for statistics).
    pub packet_len: u32,
}

impl PacketInfo {
    /// Create a new [`PacketInfo`] with the given fields.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        protocol: Protocol,
        direction: PacketDirection,
        iface_index: u32,
        packet_len: u32,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            direction,
            iface_index,
            packet_len,
        }
    }
}

impl Default for PacketInfo {
    fn default() -> Self {
        Self {
            src_ip: [0; 4],
            dst_ip: [0; 4],
            src_port: 0,
            dst_port: 0,
            protocol: Protocol::Any,
            direction: PacketDirection::Incoming,
            iface_index: 0,
            packet_len: 0,
        }
    }
}

// =========================================================================
// FilterRule
// =========================================================================

/// A single packet filter rule with match criteria and action.
///
/// All criteria fields default to wildcard (match everything).  A
/// packet must satisfy **all** non-wildcard criteria for the rule
/// to match.
#[derive(Debug, Clone, Copy)]
pub struct FilterRule {
    /// Source IP/mask to match against.
    pub src_ip: IpMask,
    /// Destination IP/mask to match against.
    pub dst_ip: IpMask,
    /// Source port range to match.
    pub src_port: PortRange,
    /// Destination port range to match.
    pub dst_port: PortRange,
    /// Protocol selector.
    pub protocol: Protocol,
    /// Action to take when this rule matches.
    pub action: FilterAction,
    /// Per-rule hit statistics.
    pub stats: RuleStats,
    /// Whether this rule slot is occupied.
    valid: bool,
}

impl FilterRule {
    /// Create an empty, invalid rule.
    const fn empty() -> Self {
        Self {
            src_ip: IpMask::ANY,
            dst_ip: IpMask::ANY,
            src_port: PortRange::ANY,
            dst_port: PortRange::ANY,
            protocol: Protocol::Any,
            action: FilterAction::Accept,
            stats: RuleStats::new(),
            valid: false,
        }
    }

    /// Create a new filter rule with the given criteria.
    pub const fn new(
        src_ip: IpMask,
        dst_ip: IpMask,
        src_port: PortRange,
        dst_port: PortRange,
        protocol: Protocol,
        action: FilterAction,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            action,
            stats: RuleStats::new(),
            valid: true,
        }
    }

    /// Check whether `pkt` matches all of this rule's criteria.
    pub const fn matches(&self, pkt: &PacketInfo) -> bool {
        if !self.valid {
            return false;
        }
        if !self.src_ip.matches(&pkt.src_ip) {
            return false;
        }
        if !self.dst_ip.matches(&pkt.dst_ip) {
            return false;
        }
        if !self.src_port.matches(pkt.src_port) {
            return false;
        }
        if !self.dst_port.matches(pkt.dst_port) {
            return false;
        }
        // Protocol::Any matches everything.
        match self.protocol {
            Protocol::Any => true,
            _ => {
                // Compare discriminant manually for const context.
                matches!(
                    (&self.protocol, &pkt.protocol),
                    (Protocol::Tcp, Protocol::Tcp)
                        | (Protocol::Udp, Protocol::Udp)
                        | (Protocol::Icmp, Protocol::Icmp)
                )
            }
        }
    }
}

impl Default for FilterRule {
    fn default() -> Self {
        Self::empty()
    }
}

// =========================================================================
// FilterChain
// =========================================================================

/// Maximum number of rules per chain.
const MAX_CHAIN_RULES: usize = 64;

/// An ordered list of filter rules with a default policy.
///
/// Rules are evaluated in order; the first matching rule determines
/// the action.  If no rule matches, the chain's default policy
/// applies.  [`FilterAction::Log`] rules do not terminate
/// evaluation — processing continues with the next rule after
/// recording the match.
pub struct FilterChain {
    /// The type of this chain (input/output/forward).
    pub chain_type: ChainType,
    /// Default policy when no rule matches.
    pub default_policy: FilterAction,
    /// Ordered array of filter rules.
    rules: [FilterRule; MAX_CHAIN_RULES],
}

impl FilterChain {
    /// Create an empty chain of the given type with the specified
    /// default policy.
    pub const fn new(chain_type: ChainType, default_policy: FilterAction) -> Self {
        Self {
            chain_type,
            default_policy,
            rules: [FilterRule::empty(); MAX_CHAIN_RULES],
        }
    }

    /// Evaluate a packet against this chain's rules.
    ///
    /// Returns the action determined by the first matching
    /// non-[`Log`](FilterAction::Log) rule, or the default policy
    /// if no rule matches.  [`Log`](FilterAction::Log) rules
    /// update their counters but do not stop evaluation.
    pub fn evaluate(&mut self, pkt: &PacketInfo) -> FilterAction {
        let byte_count = pkt.packet_len as u64;

        for rule in &mut self.rules {
            if !rule.valid {
                continue;
            }
            if rule.matches(pkt) {
                rule.stats.record(byte_count);
                match rule.action {
                    FilterAction::Log => {
                        // Log rules continue evaluation.
                    }
                    action => {
                        return action;
                    }
                }
            }
        }

        self.default_policy
    }

    /// Append a rule at the first available slot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the chain is full.
    pub fn add_rule(&mut self, rule: FilterRule) -> Result<usize> {
        for (i, slot) in self.rules.iter_mut().enumerate() {
            if !slot.valid {
                *slot = rule;
                slot.valid = true;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Delete the rule at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of
    /// bounds.  Returns [`Error::NotFound`] if the slot is already
    /// empty.
    pub fn delete_rule(&mut self, index: usize) -> Result<()> {
        if index >= MAX_CHAIN_RULES {
            return Err(Error::InvalidArgument);
        }
        if !self.rules[index].valid {
            return Err(Error::NotFound);
        }
        self.rules[index].valid = false;
        self.rules[index].stats.reset();
        Ok(())
    }

    /// Remove all rules from this chain.
    pub fn flush(&mut self) {
        for rule in &mut self.rules {
            rule.valid = false;
            rule.stats.reset();
        }
    }

    /// Return the number of active rules.
    pub fn count(&self) -> usize {
        let mut n: usize = 0;
        for rule in &self.rules {
            if rule.valid {
                n = n.saturating_add(1);
            }
        }
        n
    }

    /// Return a reference to the rule at `index`, if valid.
    pub fn get_rule(&self, index: usize) -> Option<&FilterRule> {
        if index >= MAX_CHAIN_RULES {
            return None;
        }
        if self.rules[index].valid {
            Some(&self.rules[index])
        } else {
            None
        }
    }
}

impl Default for FilterChain {
    fn default() -> Self {
        Self::new(ChainType::Input, FilterAction::Accept)
    }
}

// =========================================================================
// NatEntry
// =========================================================================

/// A single Network Address Translation mapping.
///
/// Maps an original (pre-NAT) address:port pair to a translated
/// (post-NAT) address:port pair for a specific protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatEntry {
    /// Original source/destination IP address.
    pub original_addr: [u8; 4],
    /// Original source/destination port.
    pub original_port: u16,
    /// Translated IP address.
    pub translated_addr: [u8; 4],
    /// Translated port.
    pub translated_port: u16,
    /// Protocol this mapping applies to.
    pub protocol: Protocol,
    /// Remaining lifetime in seconds (0 = expired).
    pub timeout: u32,
    /// Whether this entry is occupied.
    valid: bool,
}

impl NatEntry {
    /// Create an empty, invalid NAT entry.
    const fn empty() -> Self {
        Self {
            original_addr: [0; 4],
            original_port: 0,
            translated_addr: [0; 4],
            translated_port: 0,
            protocol: Protocol::Any,
            timeout: 0,
            valid: false,
        }
    }

    /// Create a new NAT entry.
    pub const fn new(
        original_addr: [u8; 4],
        original_port: u16,
        translated_addr: [u8; 4],
        translated_port: u16,
        protocol: Protocol,
        timeout: u32,
    ) -> Self {
        Self {
            original_addr,
            original_port,
            translated_addr,
            translated_port,
            protocol,
            timeout,
            valid: true,
        }
    }

    /// Check whether this entry matches a packet's address, port,
    /// and protocol (on the original side).
    pub const fn matches_original(&self, addr: &[u8; 4], port: u16, proto: Protocol) -> bool {
        if !self.valid || self.timeout == 0 {
            return false;
        }
        if self.original_addr[0] != addr[0]
            || self.original_addr[1] != addr[1]
            || self.original_addr[2] != addr[2]
            || self.original_addr[3] != addr[3]
        {
            return false;
        }
        if self.original_port != port {
            return false;
        }
        matches!(
            (&self.protocol, &proto),
            (Protocol::Any, _)
                | (Protocol::Tcp, Protocol::Tcp)
                | (Protocol::Udp, Protocol::Udp)
                | (Protocol::Icmp, Protocol::Icmp)
        )
    }

    /// Check whether this entry matches a packet's address, port,
    /// and protocol (on the translated side).
    pub const fn matches_translated(&self, addr: &[u8; 4], port: u16, proto: Protocol) -> bool {
        if !self.valid || self.timeout == 0 {
            return false;
        }
        if self.translated_addr[0] != addr[0]
            || self.translated_addr[1] != addr[1]
            || self.translated_addr[2] != addr[2]
            || self.translated_addr[3] != addr[3]
        {
            return false;
        }
        if self.translated_port != port {
            return false;
        }
        matches!(
            (&self.protocol, &proto),
            (Protocol::Any, _)
                | (Protocol::Tcp, Protocol::Tcp)
                | (Protocol::Udp, Protocol::Udp)
                | (Protocol::Icmp, Protocol::Icmp)
        )
    }
}

impl Default for NatEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// =========================================================================
// NatTable
// =========================================================================

/// Maximum number of NAT entries.
const MAX_NAT_ENTRIES: usize = 128;

/// Table of active NAT translation mappings.
///
/// Holds up to [`MAX_NAT_ENTRIES`] (128) entries.  Provides lookup
/// by original or translated address/port, insertion, removal, and
/// timeout-based expiration.
pub struct NatTable {
    /// Fixed-size array of NAT entries.
    entries: [NatEntry; MAX_NAT_ENTRIES],
}

impl NatTable {
    /// Create an empty NAT table.
    pub const fn new() -> Self {
        Self {
            entries: [NatEntry::empty(); MAX_NAT_ENTRIES],
        }
    }

    /// Add a new NAT mapping.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    /// Returns [`Error::AlreadyExists`] if an identical mapping
    /// already exists.
    pub fn add(&mut self, entry: NatEntry) -> Result<usize> {
        // Check for duplicates.
        for e in &self.entries {
            if e.valid
                && e.original_addr == entry.original_addr
                && e.original_port == entry.original_port
                && e.translated_addr == entry.translated_addr
                && e.translated_port == entry.translated_port
            {
                return Err(Error::AlreadyExists);
            }
        }
        // Find first free slot.
        for (i, slot) in self.entries.iter_mut().enumerate() {
            if !slot.valid {
                *slot = entry;
                slot.valid = true;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove the NAT entry at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of
    /// bounds.  Returns [`Error::NotFound`] if the slot is empty.
    pub fn remove(&mut self, index: usize) -> Result<()> {
        if index >= MAX_NAT_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        if !self.entries[index].valid {
            return Err(Error::NotFound);
        }
        self.entries[index].valid = false;
        Ok(())
    }

    /// Look up a NAT entry by original address, port, and
    /// protocol.
    ///
    /// Returns the entry and its index if found.
    pub fn lookup_original(
        &self,
        addr: &[u8; 4],
        port: u16,
        proto: Protocol,
    ) -> Option<(usize, &NatEntry)> {
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.matches_original(addr, port, proto) {
                return Some((i, entry));
            }
        }
        None
    }

    /// Look up a NAT entry by translated address, port, and
    /// protocol.
    ///
    /// Returns the entry and its index if found.
    pub fn lookup_translated(
        &self,
        addr: &[u8; 4],
        port: u16,
        proto: Protocol,
    ) -> Option<(usize, &NatEntry)> {
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.matches_translated(addr, port, proto) {
                return Some((i, entry));
            }
        }
        None
    }

    /// Decrement all entry timeouts by `seconds` and invalidate
    /// any that reach zero.
    ///
    /// Returns the number of entries that expired.
    pub fn expire(&mut self, seconds: u32) -> usize {
        let mut expired: usize = 0;
        for entry in &mut self.entries {
            if entry.valid && entry.timeout > 0 {
                if entry.timeout <= seconds {
                    entry.timeout = 0;
                    entry.valid = false;
                    expired = expired.saturating_add(1);
                } else {
                    entry.timeout = entry.timeout.saturating_sub(seconds);
                }
            }
        }
        expired
    }

    /// Return the number of active entries.
    pub fn count(&self) -> usize {
        let mut n: usize = 0;
        for entry in &self.entries {
            if entry.valid {
                n = n.saturating_add(1);
            }
        }
        n
    }

    /// Remove all entries.
    pub fn flush(&mut self) {
        for entry in &mut self.entries {
            entry.valid = false;
        }
    }
}

impl Default for NatTable {
    fn default() -> Self {
        Self::new()
    }
}

// =========================================================================
// Firewall
// =========================================================================

/// Top-level packet filter aggregating three chains and a NAT table.
///
/// The [`Firewall`] holds an input, output, and forward chain plus
/// a [`NatTable`].  The [`process_packet`](Self::process_packet)
/// method selects the appropriate chain based on packet direction,
/// evaluates it, and returns the resulting [`FilterAction`].
pub struct Firewall {
    /// Chain for packets destined to this host.
    pub input: FilterChain,
    /// Chain for packets originating from this host.
    pub output: FilterChain,
    /// Chain for packets being routed through this host.
    pub forward: FilterChain,
    /// Network address translation table.
    pub nat: NatTable,
}

impl Firewall {
    /// Create a new firewall with empty chains and default-accept
    /// policies.
    pub const fn new() -> Self {
        Self {
            input: FilterChain::new(ChainType::Input, FilterAction::Accept),
            output: FilterChain::new(ChainType::Output, FilterAction::Accept),
            forward: FilterChain::new(ChainType::Forward, FilterAction::Accept),
            nat: NatTable::new(),
        }
    }

    /// Add a rule to the specified chain.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the target chain is full.
    pub fn add_rule(&mut self, chain: ChainType, rule: FilterRule) -> Result<usize> {
        self.chain_mut(chain).add_rule(rule)
    }

    /// Delete a rule from the specified chain by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the index is out of
    /// bounds, or [`Error::NotFound`] if the slot is empty.
    pub fn delete_rule(&mut self, chain: ChainType, index: usize) -> Result<()> {
        self.chain_mut(chain).delete_rule(index)
    }

    /// Remove all rules from the specified chain.
    pub fn flush(&mut self, chain: ChainType) {
        self.chain_mut(chain).flush();
    }

    /// Remove all rules from all chains and clear the NAT table.
    pub fn flush_all(&mut self) {
        self.input.flush();
        self.output.flush();
        self.forward.flush();
        self.nat.flush();
    }

    /// Process a packet through the appropriate chain.
    ///
    /// Selects the chain based on `pkt.direction`:
    /// - [`Incoming`](PacketDirection::Incoming) packets go
    ///   through the input chain.
    /// - [`Outgoing`](PacketDirection::Outgoing) packets go
    ///   through the output chain.
    ///
    /// For forwarded packets, call
    /// [`process_forward`](Self::process_forward) explicitly.
    pub fn process_packet(&mut self, pkt: &PacketInfo) -> FilterAction {
        match pkt.direction {
            PacketDirection::Incoming => self.input.evaluate(pkt),
            PacketDirection::Outgoing => self.output.evaluate(pkt),
        }
    }

    /// Process a packet through the forward chain.
    pub fn process_forward(&mut self, pkt: &PacketInfo) -> FilterAction {
        self.forward.evaluate(pkt)
    }

    /// Return a mutable reference to the chain of the given type.
    fn chain_mut(&mut self, chain: ChainType) -> &mut FilterChain {
        match chain {
            ChainType::Input => &mut self.input,
            ChainType::Output => &mut self.output,
            ChainType::Forward => &mut self.forward,
        }
    }
}

impl Default for Firewall {
    fn default() -> Self {
        Self::new()
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- IpMask -----------------------------------------------------------

    #[test]
    fn test_ip_mask_any_matches_all() {
        let mask = IpMask::ANY;
        assert!(mask.matches(&[10, 0, 0, 1]));
        assert!(mask.matches(&[192, 168, 1, 1]));
        assert!(mask.matches(&[255, 255, 255, 255]));
    }

    #[test]
    fn test_ip_mask_host_match() {
        let mask = IpMask {
            addr: [192, 168, 1, 100],
            prefix_len: 32,
        };
        assert!(mask.matches(&[192, 168, 1, 100]));
        assert!(!mask.matches(&[192, 168, 1, 101]));
    }

    #[test]
    fn test_ip_mask_cidr_24() {
        let mask = IpMask {
            addr: [10, 0, 0, 0],
            prefix_len: 24,
        };
        assert!(mask.matches(&[10, 0, 0, 1]));
        assert!(mask.matches(&[10, 0, 0, 255]));
        assert!(!mask.matches(&[10, 0, 1, 0]));
    }

    #[test]
    fn test_ip_mask_cidr_16() {
        let mask = IpMask {
            addr: [172, 16, 0, 0],
            prefix_len: 16,
        };
        assert!(mask.matches(&[172, 16, 0, 1]));
        assert!(mask.matches(&[172, 16, 255, 255]));
        assert!(!mask.matches(&[172, 17, 0, 0]));
    }

    #[test]
    fn test_ip_mask_new_invalid_prefix() {
        assert_eq!(IpMask::new([0; 4], 33), Err(Error::InvalidArgument));
    }

    // -- PortRange --------------------------------------------------------

    #[test]
    fn test_port_range_any() {
        let range = PortRange::ANY;
        assert!(range.matches(0));
        assert!(range.matches(80));
        assert!(range.matches(65535));
    }

    #[test]
    fn test_port_range_exact() {
        let range = PortRange { min: 443, max: 443 };
        assert!(range.matches(443));
        assert!(!range.matches(80));
    }

    #[test]
    fn test_port_range_span() {
        let range = PortRange {
            min: 1024,
            max: 65535,
        };
        assert!(!range.matches(80));
        assert!(range.matches(1024));
        assert!(range.matches(8080));
        assert!(range.matches(65535));
    }

    #[test]
    fn test_port_range_new_invalid() {
        assert_eq!(PortRange::new(100, 50), Err(Error::InvalidArgument));
    }

    // -- RuleStats --------------------------------------------------------

    #[test]
    fn test_rule_stats_record_and_reset() {
        let mut stats = RuleStats::new();
        assert_eq!(stats.packets, 0);
        assert_eq!(stats.bytes, 0);

        stats.record(100);
        stats.record(200);
        assert_eq!(stats.packets, 2);
        assert_eq!(stats.bytes, 300);

        stats.reset();
        assert_eq!(stats.packets, 0);
        assert_eq!(stats.bytes, 0);
    }

    // -- FilterRule -------------------------------------------------------

    #[test]
    fn test_filter_rule_wildcard_matches_all() {
        let rule = FilterRule::new(
            IpMask::ANY,
            IpMask::ANY,
            PortRange::ANY,
            PortRange::ANY,
            Protocol::Any,
            FilterAction::Accept,
        );
        let pkt = PacketInfo::new(
            [10, 0, 0, 1],
            [192, 168, 1, 1],
            12345,
            80,
            Protocol::Tcp,
            PacketDirection::Incoming,
            1,
            100,
        );
        assert!(rule.matches(&pkt));
    }

    #[test]
    fn test_filter_rule_protocol_mismatch() {
        let rule = FilterRule::new(
            IpMask::ANY,
            IpMask::ANY,
            PortRange::ANY,
            PortRange::ANY,
            Protocol::Udp,
            FilterAction::Drop,
        );
        let pkt = PacketInfo::new(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            Protocol::Tcp,
            PacketDirection::Incoming,
            0,
            64,
        );
        assert!(!rule.matches(&pkt));
    }

    #[test]
    fn test_filter_rule_src_ip_mismatch() {
        let rule = FilterRule::new(
            IpMask {
                addr: [192, 168, 1, 0],
                prefix_len: 24,
            },
            IpMask::ANY,
            PortRange::ANY,
            PortRange::ANY,
            Protocol::Any,
            FilterAction::Drop,
        );
        let pkt = PacketInfo::new(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            0,
            0,
            Protocol::Icmp,
            PacketDirection::Incoming,
            0,
            64,
        );
        assert!(!rule.matches(&pkt));
    }

    // -- FilterChain ------------------------------------------------------

    #[test]
    fn test_chain_default_policy() {
        let mut chain = FilterChain::new(ChainType::Input, FilterAction::Drop);
        let pkt = PacketInfo::default();
        assert_eq!(chain.evaluate(&pkt), FilterAction::Drop);
    }

    #[test]
    fn test_chain_first_match_wins() {
        let mut chain = FilterChain::new(ChainType::Input, FilterAction::Accept);
        // Rule 0: drop TCP port 80.
        let rule_drop = FilterRule::new(
            IpMask::ANY,
            IpMask::ANY,
            PortRange::ANY,
            PortRange { min: 80, max: 80 },
            Protocol::Tcp,
            FilterAction::Drop,
        );
        // Rule 1: accept everything.
        let rule_accept = FilterRule::new(
            IpMask::ANY,
            IpMask::ANY,
            PortRange::ANY,
            PortRange::ANY,
            Protocol::Any,
            FilterAction::Accept,
        );
        chain.add_rule(rule_drop).ok();
        chain.add_rule(rule_accept).ok();

        let pkt_http = PacketInfo::new(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            12345,
            80,
            Protocol::Tcp,
            PacketDirection::Incoming,
            1,
            100,
        );
        assert_eq!(chain.evaluate(&pkt_http), FilterAction::Drop);

        let pkt_ssh = PacketInfo::new(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            12345,
            22,
            Protocol::Tcp,
            PacketDirection::Incoming,
            1,
            100,
        );
        assert_eq!(chain.evaluate(&pkt_ssh), FilterAction::Accept);
    }

    #[test]
    fn test_chain_add_delete_flush() {
        let mut chain = FilterChain::new(ChainType::Output, FilterAction::Accept);
        assert_eq!(chain.count(), 0);

        let rule = FilterRule::new(
            IpMask::ANY,
            IpMask::ANY,
            PortRange::ANY,
            PortRange::ANY,
            Protocol::Any,
            FilterAction::Drop,
        );
        let idx = chain.add_rule(rule);
        assert!(idx.is_ok());
        assert_eq!(chain.count(), 1);

        let idx = idx.unwrap_or(0);
        assert!(chain.get_rule(idx).is_some());
        assert!(chain.delete_rule(idx).is_ok());
        assert_eq!(chain.count(), 0);

        // Re-add and flush.
        chain.add_rule(rule).ok();
        chain.add_rule(rule).ok();
        assert_eq!(chain.count(), 2);
        chain.flush();
        assert_eq!(chain.count(), 0);
    }

    #[test]
    fn test_chain_stats_update() {
        let mut chain = FilterChain::new(ChainType::Input, FilterAction::Accept);
        let rule = FilterRule::new(
            IpMask::ANY,
            IpMask::ANY,
            PortRange::ANY,
            PortRange::ANY,
            Protocol::Any,
            FilterAction::Accept,
        );
        let idx = chain.add_rule(rule).unwrap_or(0);

        let pkt = PacketInfo::new(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            0,
            0,
            Protocol::Icmp,
            PacketDirection::Incoming,
            0,
            128,
        );
        chain.evaluate(&pkt);
        chain.evaluate(&pkt);

        let r = chain.get_rule(idx);
        assert!(r.is_some());
        if let Some(r) = r {
            assert_eq!(r.stats.packets, 2);
            assert_eq!(r.stats.bytes, 256);
        }
    }

    // -- NatTable ---------------------------------------------------------

    #[test]
    fn test_nat_add_and_lookup() {
        let mut table = NatTable::new();
        let entry = NatEntry::new(
            [192, 168, 1, 100],
            12345,
            [203, 0, 113, 1],
            54321,
            Protocol::Tcp,
            300,
        );
        let idx = table.add(entry);
        assert!(idx.is_ok());

        let found = table.lookup_original(&[192, 168, 1, 100], 12345, Protocol::Tcp);
        assert!(found.is_some());
        if let Some((_, e)) = found {
            assert_eq!(e.translated_addr, [203, 0, 113, 1]);
            assert_eq!(e.translated_port, 54321);
        }

        let found = table.lookup_translated(&[203, 0, 113, 1], 54321, Protocol::Tcp);
        assert!(found.is_some());
        if let Some((_, e)) = found {
            assert_eq!(e.original_addr, [192, 168, 1, 100]);
        }
    }

    #[test]
    fn test_nat_duplicate_rejected() {
        let mut table = NatTable::new();
        let entry = NatEntry::new(
            [10, 0, 0, 1],
            1000,
            [203, 0, 113, 1],
            2000,
            Protocol::Udp,
            60,
        );
        assert!(table.add(entry).is_ok());
        assert_eq!(table.add(entry), Err(Error::AlreadyExists));
    }

    #[test]
    fn test_nat_remove() {
        let mut table = NatTable::new();
        let entry = NatEntry::new([10, 0, 0, 1], 80, [1, 2, 3, 4], 8080, Protocol::Tcp, 120);
        let idx = table.add(entry).unwrap_or(0);
        assert_eq!(table.count(), 1);
        assert!(table.remove(idx).is_ok());
        assert_eq!(table.count(), 0);
    }

    #[test]
    fn test_nat_expire() {
        let mut table = NatTable::new();
        let e1 = NatEntry::new([10, 0, 0, 1], 80, [1, 2, 3, 4], 80, Protocol::Tcp, 10);
        let e2 = NatEntry::new([10, 0, 0, 2], 80, [1, 2, 3, 5], 80, Protocol::Tcp, 100);
        table.add(e1).ok();
        table.add(e2).ok();
        assert_eq!(table.count(), 2);

        let expired = table.expire(10);
        assert_eq!(expired, 1);
        assert_eq!(table.count(), 1);
    }

    #[test]
    fn test_nat_flush() {
        let mut table = NatTable::new();
        for i in 0u8..5 {
            let e = NatEntry::new([10, 0, 0, i], 80, [1, 2, 3, i], 80, Protocol::Tcp, 60);
            table.add(e).ok();
        }
        assert_eq!(table.count(), 5);
        table.flush();
        assert_eq!(table.count(), 0);
    }

    // -- Firewall ---------------------------------------------------------

    #[test]
    fn test_firewall_process_packet_input() {
        let mut fw = Firewall::new();
        // Drop all incoming TCP to port 22.
        let rule = FilterRule::new(
            IpMask::ANY,
            IpMask::ANY,
            PortRange::ANY,
            PortRange { min: 22, max: 22 },
            Protocol::Tcp,
            FilterAction::Drop,
        );
        fw.add_rule(ChainType::Input, rule).ok();

        let pkt_ssh = PacketInfo::new(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            54321,
            22,
            Protocol::Tcp,
            PacketDirection::Incoming,
            1,
            64,
        );
        assert_eq!(fw.process_packet(&pkt_ssh), FilterAction::Drop,);

        // Port 80 should be accepted (default policy).
        let pkt_http = PacketInfo::new(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            54321,
            80,
            Protocol::Tcp,
            PacketDirection::Incoming,
            1,
            64,
        );
        assert_eq!(fw.process_packet(&pkt_http), FilterAction::Accept,);
    }

    #[test]
    fn test_firewall_process_packet_output() {
        let mut fw = Firewall::new();
        let rule = FilterRule::new(
            IpMask::ANY,
            IpMask {
                addr: [192, 168, 1, 0],
                prefix_len: 24,
            },
            PortRange::ANY,
            PortRange::ANY,
            Protocol::Any,
            FilterAction::Reject,
        );
        fw.add_rule(ChainType::Output, rule).ok();

        let pkt = PacketInfo::new(
            [10, 0, 0, 1],
            [192, 168, 1, 50],
            0,
            0,
            Protocol::Icmp,
            PacketDirection::Outgoing,
            0,
            64,
        );
        assert_eq!(fw.process_packet(&pkt), FilterAction::Reject,);
    }

    #[test]
    fn test_firewall_forward_chain() {
        let mut fw = Firewall::new();
        fw.forward.default_policy = FilterAction::Drop;

        let pkt = PacketInfo::new(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            0,
            0,
            Protocol::Icmp,
            PacketDirection::Incoming,
            0,
            64,
        );
        assert_eq!(fw.process_forward(&pkt), FilterAction::Drop,);
    }

    #[test]
    fn test_firewall_flush_all() {
        let mut fw = Firewall::new();
        let rule = FilterRule::new(
            IpMask::ANY,
            IpMask::ANY,
            PortRange::ANY,
            PortRange::ANY,
            Protocol::Any,
            FilterAction::Drop,
        );
        fw.add_rule(ChainType::Input, rule).ok();
        fw.add_rule(ChainType::Output, rule).ok();
        fw.add_rule(ChainType::Forward, rule).ok();
        fw.nat
            .add(NatEntry::new(
                [10, 0, 0, 1],
                80,
                [1, 2, 3, 4],
                80,
                Protocol::Tcp,
                60,
            ))
            .ok();

        fw.flush_all();
        assert_eq!(fw.input.count(), 0);
        assert_eq!(fw.output.count(), 0);
        assert_eq!(fw.forward.count(), 0);
        assert_eq!(fw.nat.count(), 0);
    }

    // -- Default impls verified -------------------------------------------

    #[test]
    fn test_defaults() {
        let _ = Protocol::default();
        let _ = FilterAction::default();
        let _ = ChainType::default();
        let _ = PacketDirection::default();
        let _ = IpMask::default();
        let _ = PortRange::default();
        let _ = RuleStats::default();
        let _ = PacketInfo::default();
        let _ = FilterRule::default();
        let _ = FilterChain::default();
        let _ = NatEntry::default();
        let _ = NatTable::default();
        let _ = Firewall::default();
    }
}
