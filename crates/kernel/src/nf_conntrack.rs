// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Stateful connection tracking (conntrack) for the ONCRIX kernel.
//!
//! Provides a 5-tuple based connection tracking table inspired by
//! Linux `nf_conntrack`.  Each connection is identified by source IP,
//! destination IP, source port, destination port, and protocol, and
//! moves through states: NEW, ESTABLISHED, RELATED, and INVALID.
//!
//! The table uses fixed-size storage (256 entries) with hash-based
//! lookup on the 5-tuple.  Entries age out after a configurable
//! timeout and can be explicitly removed.
//!
//! # Integration
//!
//! This module is designed to work alongside the stateless
//! [`super::netfilter`] firewall.  Packet filtering can consult
//! connection state to allow return traffic for established flows
//! without explicit per-direction rules.

use oncrix_lib::{Error, Result};

// =========================================================================
// Constants
// =========================================================================

/// Maximum number of connection tracking entries.
const CONNTRACK_TABLE_SIZE: usize = 256;

/// Default timeout for established TCP connections (ticks).
const TCP_ESTABLISHED_TIMEOUT: u64 = 432_000;

/// Default timeout for established UDP flows (ticks).
const UDP_ESTABLISHED_TIMEOUT: u64 = 180;

/// Default timeout for new (half-open) connections (ticks).
const NEW_TIMEOUT: u64 = 120;

/// Default timeout for ICMP flows (ticks).
const ICMP_TIMEOUT: u64 = 30;

// =========================================================================
// ConnTrackProtocol
// =========================================================================

/// IP protocol for connection tracking classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnTrackProtocol {
    /// TCP (protocol 6).
    Tcp,
    /// UDP (protocol 17).
    Udp,
    /// ICMP (protocol 1).
    Icmp,
    /// Any other IP protocol, stored by number.
    Other(u8),
}

impl ConnTrackProtocol {
    /// Create from an IP protocol number.
    pub const fn from_proto_num(num: u8) -> Self {
        match num {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            n => Self::Other(n),
        }
    }

    /// Return the IP protocol number.
    pub const fn to_proto_num(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Icmp => 1,
            Self::Other(n) => n,
        }
    }

    /// Return the default timeout for this protocol's established
    /// state (in ticks).
    pub const fn default_timeout(self) -> u64 {
        match self {
            Self::Tcp => TCP_ESTABLISHED_TIMEOUT,
            Self::Udp => UDP_ESTABLISHED_TIMEOUT,
            Self::Icmp => ICMP_TIMEOUT,
            Self::Other(_) => NEW_TIMEOUT,
        }
    }
}

// =========================================================================
// ConnTrackState
// =========================================================================

/// Connection tracking state.
///
/// Mirrors the Linux conntrack states used in iptables `-m state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnTrackState {
    /// First packet of a flow has been seen (e.g. TCP SYN).
    #[default]
    New,
    /// Bidirectional traffic has been observed (e.g. SYN-ACK
    /// received).
    Established,
    /// Flow is related to an existing established connection (e.g.
    /// ICMP error for an established TCP flow, FTP data channel).
    Related,
    /// Packet does not match any known flow and is not valid for
    /// starting a new one (e.g. TCP ACK without SYN).
    Invalid,
}

// =========================================================================
// ConnTrackTuple — the 5-tuple key
// =========================================================================

/// A 5-tuple identifying one direction of a connection.
///
/// Two tuples (original and reply) together fully identify a
/// bidirectional flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnTrackTuple {
    /// Source IPv4 address.
    pub src_ip: [u8; 4],
    /// Destination IPv4 address.
    pub dst_ip: [u8; 4],
    /// Source port (0 for ICMP).
    pub src_port: u16,
    /// Destination port (0 for ICMP).
    pub dst_port: u16,
    /// IP protocol.
    pub protocol: ConnTrackProtocol,
}

impl ConnTrackTuple {
    /// Create a new 5-tuple.
    pub const fn new(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        protocol: ConnTrackProtocol,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        }
    }

    /// Return the reverse tuple (swap src and dst).
    pub const fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
        }
    }

    /// Compute a simple hash of this tuple for table indexing.
    ///
    /// Uses a Jenkins one-at-a-time variant for reasonable
    /// distribution across the fixed-size table.
    pub const fn hash(&self) -> usize {
        let mut h: u32 = 0;

        // Mix source IP
        h = h.wrapping_add(self.src_ip[0] as u32);
        h = h.wrapping_add(h << 10);
        h ^= h >> 6;
        h = h.wrapping_add(self.src_ip[1] as u32);
        h = h.wrapping_add(h << 10);
        h ^= h >> 6;
        h = h.wrapping_add(self.src_ip[2] as u32);
        h = h.wrapping_add(h << 10);
        h ^= h >> 6;
        h = h.wrapping_add(self.src_ip[3] as u32);
        h = h.wrapping_add(h << 10);
        h ^= h >> 6;

        // Mix dest IP
        h = h.wrapping_add(self.dst_ip[0] as u32);
        h = h.wrapping_add(h << 10);
        h ^= h >> 6;
        h = h.wrapping_add(self.dst_ip[1] as u32);
        h = h.wrapping_add(h << 10);
        h ^= h >> 6;
        h = h.wrapping_add(self.dst_ip[2] as u32);
        h = h.wrapping_add(h << 10);
        h ^= h >> 6;
        h = h.wrapping_add(self.dst_ip[3] as u32);
        h = h.wrapping_add(h << 10);
        h ^= h >> 6;

        // Mix ports
        h = h.wrapping_add((self.src_port >> 8) as u32);
        h = h.wrapping_add(h << 10);
        h ^= h >> 6;
        h = h.wrapping_add((self.src_port & 0xFF) as u32);
        h = h.wrapping_add(h << 10);
        h ^= h >> 6;
        h = h.wrapping_add((self.dst_port >> 8) as u32);
        h = h.wrapping_add(h << 10);
        h ^= h >> 6;
        h = h.wrapping_add((self.dst_port & 0xFF) as u32);
        h = h.wrapping_add(h << 10);
        h ^= h >> 6;

        // Mix protocol
        h = h.wrapping_add(self.protocol.to_proto_num() as u32);
        h = h.wrapping_add(h << 10);
        h ^= h >> 6;

        // Finalise
        h = h.wrapping_add(h << 3);
        h ^= h >> 11;
        h = h.wrapping_add(h << 15);

        (h as usize) % CONNTRACK_TABLE_SIZE
    }
}

// =========================================================================
// TcpConnState — per-connection TCP state for finer tracking
// =========================================================================

/// Per-connection TCP state tracking for conntrack.
///
/// Tracks the TCP handshake and teardown flags so that the
/// connection tracker can accurately classify connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TcpConnState {
    /// Initial SYN sent, awaiting SYN-ACK.
    #[default]
    SynSent,
    /// SYN-ACK received, awaiting final ACK.
    SynRecv,
    /// Three-way handshake complete.
    Established,
    /// FIN sent by one side.
    FinWait,
    /// FIN sent by both sides, awaiting final ACK(s).
    CloseWait,
    /// Connection fully closed.
    Closed,
}

// =========================================================================
// ConnTrackEntry
// =========================================================================

/// A single connection tracking table entry.
///
/// Stores both the original (initiator) and reply directions,
/// the current state, timeout, and packet/byte counters.
#[derive(Debug, Clone)]
pub struct ConnTrackEntry {
    /// Whether this slot is occupied.
    pub active: bool,
    /// The original-direction 5-tuple.
    pub original: ConnTrackTuple,
    /// The reply-direction 5-tuple (reversed original).
    pub reply: ConnTrackTuple,
    /// Current conntrack state.
    pub state: ConnTrackState,
    /// TCP-specific connection tracking state (only meaningful
    /// when `protocol` is TCP).
    pub tcp_state: TcpConnState,
    /// Remaining lifetime in ticks; entry expires when this
    /// reaches zero.
    pub timeout: u64,
    /// Packets seen in the original direction.
    pub orig_packets: u64,
    /// Bytes seen in the original direction.
    pub orig_bytes: u64,
    /// Packets seen in the reply direction.
    pub reply_packets: u64,
    /// Bytes seen in the reply direction.
    pub reply_bytes: u64,
    /// Monotonic tick at which this entry was created.
    pub created_tick: u64,
    /// Mark value (for integration with netfilter rules).
    pub mark: u32,
}

impl ConnTrackEntry {
    /// Create a new entry for the given original tuple.
    const fn new(original: ConnTrackTuple, created_tick: u64) -> Self {
        let reply = original.reverse();
        let timeout = match original.protocol {
            ConnTrackProtocol::Tcp => NEW_TIMEOUT,
            other => other.default_timeout(),
        };
        Self {
            active: true,
            original,
            reply,
            state: ConnTrackState::New,
            tcp_state: TcpConnState::SynSent,
            timeout,
            orig_packets: 1,
            orig_bytes: 0,
            reply_packets: 0,
            reply_bytes: 0,
            created_tick,
            mark: 0,
        }
    }

    /// Check if this entry has expired.
    pub const fn is_expired(&self) -> bool {
        self.timeout == 0
    }

    /// Refresh the timeout to the protocol-appropriate established
    /// value.
    fn refresh_timeout(&mut self) {
        self.timeout = self.original.protocol.default_timeout();
    }
}

// =========================================================================
// ConnTrackTable
// =========================================================================

/// Fixed-size connection tracking table.
///
/// Stores up to [`CONNTRACK_TABLE_SIZE`] entries indexed by hash of
/// the 5-tuple.  Collisions are resolved by linear probing.
pub struct ConnTrackTable {
    /// Storage for connection entries.
    entries: [Option<ConnTrackEntry>; CONNTRACK_TABLE_SIZE],
    /// Number of active entries.
    count: usize,
    /// Current monotonic tick counter for timeout management.
    current_tick: u64,
    /// Total packets processed.
    total_packets: u64,
    /// Total new connections created.
    total_new: u64,
    /// Total entries that timed out.
    total_expired: u64,
}

/// Helper to create the `None`-initialised array at compile time.
const EMPTY_ENTRY: Option<ConnTrackEntry> = None;

impl ConnTrackTable {
    /// Create a new empty connection tracking table.
    pub const fn new() -> Self {
        Self {
            entries: [EMPTY_ENTRY; CONNTRACK_TABLE_SIZE],
            count: 0,
            current_tick: 0,
            total_packets: 0,
            total_new: 0,
            total_expired: 0,
        }
    }

    /// Return the number of active entries.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return the current tick.
    pub const fn current_tick(&self) -> u64 {
        self.current_tick
    }

    /// Return total packets processed.
    pub const fn total_packets(&self) -> u64 {
        self.total_packets
    }

    /// Return total new connections created.
    pub const fn total_new(&self) -> u64 {
        self.total_new
    }

    /// Return total expired entries.
    pub const fn total_expired(&self) -> u64 {
        self.total_expired
    }

    /// Advance the tick counter and expire stale entries.
    ///
    /// Call this periodically (e.g. once per timer interrupt) to
    /// age out connections that have exceeded their timeout.
    pub fn tick(&mut self, ticks: u64) {
        self.current_tick = self.current_tick.saturating_add(ticks);
        for slot in self.entries.iter_mut() {
            if let Some(entry) = slot {
                if entry.timeout <= ticks {
                    entry.active = false;
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                    self.total_expired = self.total_expired.saturating_add(1);
                } else {
                    entry.timeout -= ticks;
                }
            }
        }
    }

    /// Look up a connection by 5-tuple.
    ///
    /// Searches for a match on either the original or reply tuple.
    /// Returns a reference to the entry and a boolean indicating
    /// whether the match was on the reply direction (`true` = reply).
    pub fn lookup(&self, tuple: &ConnTrackTuple) -> Option<(&ConnTrackEntry, bool)> {
        let start = tuple.hash();
        for i in 0..CONNTRACK_TABLE_SIZE {
            let idx = (start + i) % CONNTRACK_TABLE_SIZE;
            match &self.entries[idx] {
                Some(entry) if entry.active => {
                    if entry.original == *tuple {
                        return Some((entry, false));
                    }
                    if entry.reply == *tuple {
                        return Some((entry, true));
                    }
                }
                None => return None,
                _ => {}
            }
        }
        None
    }

    /// Look up a connection by 5-tuple (mutable).
    fn lookup_mut(&mut self, tuple: &ConnTrackTuple) -> Option<(&mut ConnTrackEntry, bool)> {
        let start = tuple.hash();
        for i in 0..CONNTRACK_TABLE_SIZE {
            let idx = (start + i) % CONNTRACK_TABLE_SIZE;
            match &self.entries[idx] {
                Some(entry) if entry.active => {
                    if entry.original == *tuple {
                        let e = self.entries[idx].as_mut()?;
                        return Some((e, false));
                    }
                    if entry.reply == *tuple {
                        let e = self.entries[idx].as_mut()?;
                        return Some((e, true));
                    }
                }
                None => return None,
                _ => {}
            }
        }
        None
    }

    /// Process a packet and return its connection tracking state.
    ///
    /// If the packet matches an existing flow, the entry is updated
    /// (counters, timeout, TCP state).  If no match is found, a new
    /// entry in state NEW is created.
    ///
    /// # Arguments
    ///
    /// * `tuple` — 5-tuple extracted from the packet.
    /// * `packet_len` — total packet length in bytes (for counters).
    /// * `tcp_flags` — TCP flags from the header (`0` for non-TCP).
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full and no
    /// expired entry can be reclaimed.
    pub fn process_packet(
        &mut self,
        tuple: &ConnTrackTuple,
        packet_len: u64,
        tcp_flags: u16,
    ) -> Result<ConnTrackState> {
        self.total_packets = self.total_packets.saturating_add(1);

        // Check for existing entry
        if let Some((entry, is_reply)) = self.lookup_mut(tuple) {
            if is_reply {
                entry.reply_packets = entry.reply_packets.saturating_add(1);
                entry.reply_bytes = entry.reply_bytes.saturating_add(packet_len);
            } else {
                entry.orig_packets = entry.orig_packets.saturating_add(1);
                entry.orig_bytes = entry.orig_bytes.saturating_add(packet_len);
            }

            // State transitions
            match entry.original.protocol {
                ConnTrackProtocol::Tcp => {
                    Self::apply_tcp_state(entry, is_reply, tcp_flags);
                }
                _ => {
                    // For UDP/ICMP, seeing reply traffic promotes
                    // to ESTABLISHED
                    if is_reply && entry.state == ConnTrackState::New {
                        entry.state = ConnTrackState::Established;
                    }
                }
            }

            // Refresh timeout on activity
            entry.refresh_timeout();

            return Ok(entry.state);
        }

        // No existing entry — create new
        self.insert_new(tuple, packet_len)
    }

    /// Insert a new connection entry.
    fn insert_new(&mut self, tuple: &ConnTrackTuple, packet_len: u64) -> Result<ConnTrackState> {
        let start = tuple.hash();
        for i in 0..CONNTRACK_TABLE_SIZE {
            let idx = (start + i) % CONNTRACK_TABLE_SIZE;
            if self.entries[idx].is_none() {
                let mut entry = ConnTrackEntry::new(*tuple, self.current_tick);
                entry.orig_bytes = packet_len;
                self.entries[idx] = Some(entry);
                self.count += 1;
                self.total_new = self.total_new.saturating_add(1);
                return Ok(ConnTrackState::New);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Update TCP-specific connection state based on flags.
    fn apply_tcp_state(entry: &mut ConnTrackEntry, is_reply: bool, tcp_flags: u16) {
        // TCP flag constants (mirroring tcp.rs)
        const FIN: u16 = 0x01;
        const SYN: u16 = 0x02;
        const RST: u16 = 0x04;
        const ACK: u16 = 0x10;

        if tcp_flags & RST != 0 {
            entry.tcp_state = TcpConnState::Closed;
            entry.state = ConnTrackState::Invalid;
            entry.timeout = 10; // Quick expiry
            return;
        }

        match entry.tcp_state {
            TcpConnState::SynSent => {
                if is_reply && tcp_flags & (SYN | ACK) == (SYN | ACK) {
                    entry.tcp_state = TcpConnState::SynRecv;
                }
            }
            TcpConnState::SynRecv => {
                if !is_reply && tcp_flags & ACK != 0 {
                    entry.tcp_state = TcpConnState::Established;
                    entry.state = ConnTrackState::Established;
                    entry.refresh_timeout();
                }
            }
            TcpConnState::Established => {
                if tcp_flags & FIN != 0 {
                    entry.tcp_state = TcpConnState::FinWait;
                }
            }
            TcpConnState::FinWait => {
                if tcp_flags & FIN != 0 {
                    entry.tcp_state = TcpConnState::CloseWait;
                    entry.timeout = 120;
                }
            }
            TcpConnState::CloseWait => {
                if tcp_flags & ACK != 0 {
                    entry.tcp_state = TcpConnState::Closed;
                    entry.timeout = 10;
                }
            }
            TcpConnState::Closed => {}
        }
    }

    /// Remove a connection entry by 5-tuple.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching entry exists.
    pub fn remove(&mut self, tuple: &ConnTrackTuple) -> Result<()> {
        let start = tuple.hash();
        for i in 0..CONNTRACK_TABLE_SIZE {
            let idx = (start + i) % CONNTRACK_TABLE_SIZE;
            match &self.entries[idx] {
                Some(entry)
                    if entry.active && (entry.original == *tuple || entry.reply == *tuple) =>
                {
                    self.entries[idx] = None;
                    self.count = self.count.saturating_sub(1);
                    return Ok(());
                }
                None => return Err(Error::NotFound),
                _ => {}
            }
        }
        Err(Error::NotFound)
    }

    /// Remove all entries, resetting the table to empty.
    pub fn flush(&mut self) {
        for slot in self.entries.iter_mut() {
            *slot = None;
        }
        self.count = 0;
    }

    /// Set a mark value on a tracked connection.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching entry exists.
    pub fn set_mark(&mut self, tuple: &ConnTrackTuple, mark: u32) -> Result<()> {
        match self.lookup_mut(tuple) {
            Some((entry, _)) => {
                entry.mark = mark;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Check whether a packet belongs to a related flow.
    ///
    /// In a full implementation this would inspect ICMP error
    /// payloads and ALG (application layer gateway) data.  For now
    /// it marks ICMP packets whose embedded 5-tuple matches an
    /// existing ESTABLISHED connection as RELATED.
    pub fn check_related(&self, inner_tuple: &ConnTrackTuple) -> bool {
        if let Some((entry, _)) = self.lookup(inner_tuple) {
            return entry.state == ConnTrackState::Established;
        }
        false
    }

    /// Return statistics for a given connection.
    ///
    /// Returns `(orig_packets, orig_bytes, reply_packets,
    /// reply_bytes)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching entry exists.
    pub fn get_stats(&self, tuple: &ConnTrackTuple) -> Result<(u64, u64, u64, u64)> {
        match self.lookup(tuple) {
            Some((entry, _)) => Ok((
                entry.orig_packets,
                entry.orig_bytes,
                entry.reply_packets,
                entry.reply_bytes,
            )),
            None => Err(Error::NotFound),
        }
    }

    /// Iterate over all active entries and invoke `f` on each.
    pub fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(&ConnTrackEntry),
    {
        for entry in self.entries.iter().flatten() {
            if entry.active {
                f(entry);
            }
        }
    }

    /// Return the number of entries in a given state.
    pub fn count_by_state(&self, state: ConnTrackState) -> usize {
        let mut n = 0;
        for entry in self.entries.iter().flatten() {
            if entry.active && entry.state == state {
                n += 1;
            }
        }
        n
    }
}

// =========================================================================
// ConnTrackHelper — ALG stub
// =========================================================================

/// Application Layer Gateway (ALG) helper type.
///
/// ALG helpers inspect application-layer data to create expectation
/// entries for related connections (e.g. FTP data channels).  This
/// is a stub for future implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnTrackHelper {
    /// No helper.
    #[default]
    None,
    /// FTP helper (tracks PORT/PASV commands).
    Ftp,
    /// TFTP helper.
    Tftp,
    /// SIP helper.
    Sip,
}

// =========================================================================
// Expectation — for related connections
// =========================================================================

/// Maximum number of expectations (pending related connections).
const MAX_EXPECTATIONS: usize = 32;

/// An expectation for a related connection.
///
/// When an ALG helper detects that a new connection will be opened
/// (e.g. FTP PASV), it creates an expectation.  Incoming packets
/// matching the expectation are classified as RELATED.
#[derive(Debug, Clone, Copy)]
pub struct Expectation {
    /// Whether this slot is active.
    pub active: bool,
    /// Expected source IP (or `[0; 4]` for any).
    pub src_ip: [u8; 4],
    /// Expected destination IP.
    pub dst_ip: [u8; 4],
    /// Expected destination port.
    pub dst_port: u16,
    /// Expected protocol.
    pub protocol: ConnTrackProtocol,
    /// Remaining lifetime in ticks.
    pub timeout: u64,
    /// Tuple of the master (established) connection.
    pub master: ConnTrackTuple,
}

/// Table of pending expectations for related connections.
pub struct ExpectationTable {
    /// Expectation slots.
    entries: [Option<Expectation>; MAX_EXPECTATIONS],
    /// Number of active expectations.
    count: usize,
}

/// Compile-time initialiser for the array.
const EMPTY_EXPECT: Option<Expectation> = None;

impl ExpectationTable {
    /// Create a new empty expectation table.
    pub const fn new() -> Self {
        Self {
            entries: [EMPTY_EXPECT; MAX_EXPECTATIONS],
            count: 0,
        }
    }

    /// Return the number of active expectations.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Add an expectation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn add(
        &mut self,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        dst_port: u16,
        protocol: ConnTrackProtocol,
        timeout: u64,
        master: ConnTrackTuple,
    ) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(Expectation {
                    active: true,
                    src_ip,
                    dst_ip,
                    dst_port,
                    protocol,
                    timeout,
                    master,
                });
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Check whether a tuple matches any pending expectation.
    ///
    /// If matched, the expectation is consumed (removed) and the
    /// master connection tuple is returned.
    pub fn check_and_consume(&mut self, tuple: &ConnTrackTuple) -> Option<ConnTrackTuple> {
        for slot in self.entries.iter_mut() {
            if let Some(exp) = slot {
                if !exp.active {
                    continue;
                }
                let src_match = exp.src_ip == [0; 4] || exp.src_ip == tuple.src_ip;
                let dst_match = exp.dst_ip == tuple.dst_ip;
                let port_match = exp.dst_port == tuple.dst_port;
                let proto_match = exp.protocol.to_proto_num() == tuple.protocol.to_proto_num();

                if src_match && dst_match && port_match && proto_match {
                    let master = exp.master;
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                    return Some(master);
                }
            }
        }
        None
    }

    /// Advance ticks and expire stale expectations.
    pub fn tick(&mut self, ticks: u64) {
        for slot in self.entries.iter_mut() {
            if let Some(exp) = slot {
                if exp.timeout <= ticks {
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                } else {
                    exp.timeout -= ticks;
                }
            }
        }
    }

    /// Remove all expectations.
    pub fn flush(&mut self) {
        for slot in self.entries.iter_mut() {
            *slot = None;
        }
        self.count = 0;
    }
}

// =========================================================================
// ConnTracker — top-level API
// =========================================================================

/// Top-level connection tracker combining the connection table and
/// expectation table.
///
/// This is the primary API for the firewall / network stack to
/// classify packets by connection state.
pub struct ConnTracker {
    /// Connection tracking table.
    pub table: ConnTrackTable,
    /// Expectation table for related connections.
    pub expectations: ExpectationTable,
    /// Whether connection tracking is enabled.
    enabled: bool,
}

impl ConnTracker {
    /// Create a new connection tracker (enabled by default).
    pub const fn new() -> Self {
        Self {
            table: ConnTrackTable::new(),
            expectations: ExpectationTable::new(),
            enabled: true,
        }
    }

    /// Return whether tracking is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable connection tracking.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable connection tracking.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Process a packet through connection tracking.
    ///
    /// Returns the conntrack state of the packet.  If tracking is
    /// disabled, all packets are classified as NEW.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn process(
        &mut self,
        tuple: &ConnTrackTuple,
        packet_len: u64,
        tcp_flags: u16,
    ) -> Result<ConnTrackState> {
        if !self.enabled {
            return Ok(ConnTrackState::New);
        }

        // Check expectations first — a matching expectation means
        // the packet is RELATED
        if let Some(_master) = self.expectations.check_and_consume(tuple) {
            // Insert as a new entry but mark as RELATED
            let state = self.table.process_packet(tuple, packet_len, tcp_flags)?;
            if state == ConnTrackState::New {
                if let Some((entry, _)) = self.table.lookup_mut(tuple) {
                    entry.state = ConnTrackState::Related;
                    return Ok(ConnTrackState::Related);
                }
            }
            return Ok(state);
        }

        self.table.process_packet(tuple, packet_len, tcp_flags)
    }

    /// Advance the tick counter on both tables.
    pub fn tick(&mut self, ticks: u64) {
        self.table.tick(ticks);
        self.expectations.tick(ticks);
    }

    /// Flush all connections and expectations.
    pub fn flush(&mut self) {
        self.table.flush();
        self.expectations.flush();
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_tuple() -> ConnTrackTuple {
        ConnTrackTuple::new(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            12345,
            80,
            ConnTrackProtocol::Tcp,
        )
    }

    #[test]
    fn test_new_connection() {
        let mut ct = ConnTracker::new();
        let tuple = tcp_tuple();
        let state = ct.process(&tuple, 64, 0x02).unwrap();
        assert_eq!(state, ConnTrackState::New);
        assert_eq!(ct.table.count(), 1);
    }

    #[test]
    fn test_tcp_established() {
        let mut ct = ConnTracker::new();
        let orig = tcp_tuple();
        let reply = orig.reverse();

        // SYN
        let s = ct.process(&orig, 64, 0x02).unwrap();
        assert_eq!(s, ConnTrackState::New);

        // SYN-ACK
        let s = ct.process(&reply, 64, 0x12).unwrap();
        assert_eq!(s, ConnTrackState::New); // Not yet ESTABLISHED

        // ACK
        let s = ct.process(&orig, 64, 0x10).unwrap();
        assert_eq!(s, ConnTrackState::Established);
    }

    #[test]
    fn test_udp_established() {
        let mut ct = ConnTracker::new();
        let orig = ConnTrackTuple::new(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            5000,
            53,
            ConnTrackProtocol::Udp,
        );
        let reply = orig.reverse();

        let s = ct.process(&orig, 64, 0).unwrap();
        assert_eq!(s, ConnTrackState::New);

        let s = ct.process(&reply, 128, 0).unwrap();
        assert_eq!(s, ConnTrackState::Established);
    }

    #[test]
    fn test_timeout_expiry() {
        let mut ct = ConnTracker::new();
        let tuple = ConnTrackTuple::new(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1000,
            53,
            ConnTrackProtocol::Udp,
        );
        ct.process(&tuple, 64, 0).unwrap();
        assert_eq!(ct.table.count(), 1);

        ct.tick(UDP_ESTABLISHED_TIMEOUT + 1);
        assert_eq!(ct.table.count(), 0);
    }

    #[test]
    fn test_remove() {
        let mut ct = ConnTracker::new();
        let tuple = tcp_tuple();
        ct.process(&tuple, 64, 0x02).unwrap();
        assert_eq!(ct.table.count(), 1);

        ct.table.remove(&tuple).unwrap();
        assert_eq!(ct.table.count(), 0);
    }

    #[test]
    fn test_flush() {
        let mut ct = ConnTracker::new();
        for port in 1..=10 {
            let t = ConnTrackTuple::new(
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                port,
                80,
                ConnTrackProtocol::Tcp,
            );
            ct.process(&t, 64, 0x02).unwrap();
        }
        assert_eq!(ct.table.count(), 10);
        ct.flush();
        assert_eq!(ct.table.count(), 0);
    }

    #[test]
    fn test_disabled_tracking() {
        let mut ct = ConnTracker::new();
        ct.disable();
        let tuple = tcp_tuple();
        let s = ct.process(&tuple, 64, 0x02).unwrap();
        assert_eq!(s, ConnTrackState::New);
        assert_eq!(ct.table.count(), 0);
    }

    #[test]
    fn test_expectation() {
        let mut ct = ConnTracker::new();
        let master = tcp_tuple();
        ct.process(&master, 64, 0x02).unwrap();

        // Simulate: master connection promotes to established
        let reply = master.reverse();
        ct.process(&reply, 64, 0x12).unwrap();
        ct.process(&master, 64, 0x10).unwrap();

        // Add expectation for a related FTP data connection
        ct.expectations
            .add(
                [0; 4],
                [10, 0, 0, 1],
                20,
                ConnTrackProtocol::Tcp,
                60,
                master,
            )
            .unwrap();

        let data = ConnTrackTuple::new(
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            20,
            50000,
            ConnTrackProtocol::Tcp,
        );
        let s = ct.process(&data, 64, 0x02).unwrap();
        assert_eq!(s, ConnTrackState::Related);
    }

    #[test]
    fn test_tuple_hash_deterministic() {
        let t = tcp_tuple();
        let h1 = t.hash();
        let h2 = t.hash();
        assert_eq!(h1, h2);
        assert!(h1 < CONNTRACK_TABLE_SIZE);
    }

    #[test]
    fn test_count_by_state() {
        let mut ct = ConnTracker::new();
        for port in 1..=5 {
            let t = ConnTrackTuple::new(
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                port,
                80,
                ConnTrackProtocol::Tcp,
            );
            ct.process(&t, 64, 0x02).unwrap();
        }
        assert_eq!(ct.table.count_by_state(ConnTrackState::New), 5);
    }
}
