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

    /// Compute a direction-agnostic hash of this tuple for table indexing.
    ///
    /// The two endpoints are mixed in canonical (lowest-first) order so that a
    /// flow and its reply land in the same bucket. That is load-bearing, not
    /// cosmetic: [`ConnTrackTable`] keeps one entry per connection and tells
    /// the directions apart by comparing against `original` and `reply`. If the
    /// two directions hashed differently, a reply would start probing an
    /// unrelated chain, hit an empty slot, and be recorded as a fresh
    /// connection — pinning every flow at `New` forever.
    ///
    /// Uses a Jenkins one-at-a-time variant for reasonable distribution across
    /// the fixed-size table.
    pub const fn hash(&self) -> usize {
        const fn mix(h: u32, byte: u8) -> u32 {
            let h = h.wrapping_add(byte as u32);
            let h = h.wrapping_add(h << 10);
            h ^ (h >> 6)
        }

        // IP in the high bytes, port in the low two, so ordering the packed
        // keys orders the endpoints.
        const fn endpoint(ip: [u8; 4], port: u16) -> u64 {
            ((ip[0] as u64) << 40)
                | ((ip[1] as u64) << 32)
                | ((ip[2] as u64) << 24)
                | ((ip[3] as u64) << 16)
                | port as u64
        }

        let a = endpoint(self.src_ip, self.src_port);
        let b = endpoint(self.dst_ip, self.dst_port);
        let (first, second) = if a <= b { (a, b) } else { (b, a) };

        let mut h: u32 = 0;
        let mut shift = 40;
        loop {
            h = mix(h, (first >> shift) as u8);
            h = mix(h, (second >> shift) as u8);
            if shift == 0 {
                break;
            }
            shift -= 8;
        }

        h = mix(h, self.protocol.to_proto_num());

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
// Slot — open-addressing slot state with tombstones
// =========================================================================

/// A single hash-table slot.
///
/// Open addressing with linear probing requires distinguishing a slot
/// that was *never* used ([`Slot::Empty`]) from one whose entry was
/// *deleted* ([`Slot::Tombstone`]).  A probe must stop only at
/// `Empty`; stopping at a deleted hole would make any entry inserted
/// later in the same probe chain unreachable — a conntrack miss that
/// an attacker can weaponise into state confusion or policy bypass.
#[derive(Debug, Clone)]
enum Slot {
    /// Slot has never held an entry; terminates a probe chain.
    Empty,
    /// Slot previously held an entry that was removed; a probe must
    /// continue past it, but an insert may reclaim it.
    Tombstone,
    /// Slot holds a live connection entry.
    Occupied(ConnTrackEntry),
}

impl Slot {
    /// Borrow the contained entry, if occupied.
    const fn entry(&self) -> Option<&ConnTrackEntry> {
        match self {
            Slot::Occupied(e) => Some(e),
            _ => None,
        }
    }

    /// Mutably borrow the contained entry, if occupied.
    fn entry_mut(&mut self) -> Option<&mut ConnTrackEntry> {
        match self {
            Slot::Occupied(e) => Some(e),
            _ => None,
        }
    }
}

// =========================================================================
// ConnTrackTable
// =========================================================================

/// Fixed-size connection tracking table.
///
/// Stores up to [`CONNTRACK_TABLE_SIZE`] entries indexed by hash of
/// the 5-tuple.  Collisions are resolved by linear probing, with
/// tombstones so that deletions never sever a probe chain.
pub struct ConnTrackTable {
    /// Storage for connection entries.
    entries: [Slot; CONNTRACK_TABLE_SIZE],
    /// Number of live (occupied) entries.
    count: usize,
    /// Number of tombstone slots awaiting reclamation.
    tombstones: usize,
    /// Current monotonic tick counter for timeout management.
    current_tick: u64,
    /// Total packets processed.
    total_packets: u64,
    /// Total new connections created.
    total_new: u64,
    /// Total entries that timed out.
    total_expired: u64,
    /// Total entries evicted to make room under table pressure.
    total_evicted: u64,
}

/// Helper to create the empty-initialised array at compile time.
const EMPTY_SLOT: Slot = Slot::Empty;

impl Default for ConnTrackTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnTrackTable {
    /// Create a new empty connection tracking table.
    pub const fn new() -> Self {
        Self {
            entries: [EMPTY_SLOT; CONNTRACK_TABLE_SIZE],
            count: 0,
            tombstones: 0,
            current_tick: 0,
            total_packets: 0,
            total_new: 0,
            total_expired: 0,
            total_evicted: 0,
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

    /// Return total entries evicted under table pressure.
    pub const fn total_evicted(&self) -> u64 {
        self.total_evicted
    }

    /// Advance the tick counter and expire stale entries.
    ///
    /// Call this periodically (e.g. once per timer interrupt) to
    /// age out connections that have exceeded their timeout.  Expired
    /// slots become tombstones so that probe chains stay intact.
    pub fn tick(&mut self, ticks: u64) {
        self.current_tick = self.current_tick.saturating_add(ticks);
        for slot in self.entries.iter_mut() {
            if let Slot::Occupied(entry) = slot {
                if entry.timeout <= ticks {
                    *slot = Slot::Tombstone;
                    self.count = self.count.saturating_sub(1);
                    self.tombstones = self.tombstones.saturating_add(1);
                    self.total_expired = self.total_expired.saturating_add(1);
                } else {
                    entry.timeout = entry.timeout.saturating_sub(ticks);
                }
            }
        }
    }

    /// Look up a connection by 5-tuple.
    ///
    /// Searches for a match on either the original or reply tuple.
    /// Returns a reference to the entry and a boolean indicating
    /// whether the match was on the reply direction (`true` = reply).
    ///
    /// Probing continues past [`Slot::Tombstone`] holes and stops
    /// only at [`Slot::Empty`], so an entry inserted behind a deleted
    /// predecessor in the same chain remains reachable.
    pub fn lookup(&self, tuple: &ConnTrackTuple) -> Option<(&ConnTrackEntry, bool)> {
        let start = tuple.hash();
        for i in 0..CONNTRACK_TABLE_SIZE {
            let idx = (start + i) % CONNTRACK_TABLE_SIZE;
            match &self.entries[idx] {
                Slot::Occupied(entry) if entry.active => {
                    if entry.original == *tuple {
                        return Some((entry, false));
                    }
                    if entry.reply == *tuple {
                        return Some((entry, true));
                    }
                }
                Slot::Empty => return None,
                _ => {}
            }
        }
        None
    }

    /// Look up a connection by 5-tuple (mutable).
    ///
    /// Like [`Self::lookup`], probing skips tombstones and terminates
    /// only on an empty slot.
    fn lookup_mut(&mut self, tuple: &ConnTrackTuple) -> Option<(&mut ConnTrackEntry, bool)> {
        let start = tuple.hash();
        for i in 0..CONNTRACK_TABLE_SIZE {
            let idx = (start + i) % CONNTRACK_TABLE_SIZE;
            match &self.entries[idx] {
                Slot::Occupied(entry) if entry.active => {
                    let is_reply = if entry.original == *tuple {
                        false
                    } else if entry.reply == *tuple {
                        true
                    } else {
                        continue;
                    };
                    let e = self.entries[idx].entry_mut()?;
                    return Some((e, is_reply));
                }
                Slot::Empty => return None,
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
    ///
    /// Probes the chain for the first reclaimable slot (empty or
    /// tombstone).  If the entire table is occupied, attempts a
    /// single bounded eviction (see [`Self::evict_one`]) before
    /// retrying; only if nothing is reclaimable does it fail.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full and no
    /// entry can be evicted.
    ///
    /// # Precondition
    ///
    /// The caller MUST have performed a full-chain `lookup_mut` for `tuple`
    /// and found no match first (as `process_packet` does). `find_insert_slot`
    /// reuses the earliest `Empty`/`Tombstone` slot without re-scanning the
    /// remainder of the probe chain for a duplicate, so calling this without a
    /// preceding miss could insert a duplicate tuple and split the chain.
    fn insert_new(&mut self, tuple: &ConnTrackTuple, packet_len: u64) -> Result<ConnTrackState> {
        if let Some(idx) = self.find_insert_slot(tuple) {
            self.place_entry(idx, tuple, packet_len);
            return Ok(ConnTrackState::New);
        }

        // Table saturated on this chain with no empty/tombstone slot:
        // try to reclaim one entry, then retry the probe once.
        if self.evict_one() {
            if let Some(idx) = self.find_insert_slot(tuple) {
                self.place_entry(idx, tuple, packet_len);
                return Ok(ConnTrackState::New);
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Find the index of the first reclaimable slot along `tuple`'s
    /// probe chain, preferring the earliest tombstone or empty slot.
    fn find_insert_slot(&self, tuple: &ConnTrackTuple) -> Option<usize> {
        let start = tuple.hash();
        for i in 0..CONNTRACK_TABLE_SIZE {
            let idx = (start + i) % CONNTRACK_TABLE_SIZE;
            match &self.entries[idx] {
                Slot::Empty | Slot::Tombstone => return Some(idx),
                Slot::Occupied(_) => {}
            }
        }
        None
    }

    /// Write a fresh entry into a known-reclaimable slot, updating
    /// the live/tombstone counters.
    fn place_entry(&mut self, idx: usize, tuple: &ConnTrackTuple, packet_len: u64) {
        if matches!(self.entries[idx], Slot::Tombstone) {
            self.tombstones = self.tombstones.saturating_sub(1);
        }
        let mut entry = ConnTrackEntry::new(*tuple, self.current_tick);
        entry.orig_bytes = packet_len;
        self.entries[idx] = Slot::Occupied(entry);
        self.count = self.count.saturating_add(1);
        self.total_new = self.total_new.saturating_add(1);
    }

    /// Reclaim one slot under table pressure.
    ///
    /// Scans the whole table once (O(table)) and evicts, in priority
    /// order:
    ///
    /// 1. an already-expired entry (`timeout == 0`), if any;
    /// 2. otherwise the oldest entry still in the unconfirmed `New`
    ///    state (a half-open / flood candidate), by `created_tick`.
    ///
    /// Confirmed (`Established` / `Related`) flows are never evicted
    /// here, so an attacker flooding new tuples cannot displace a
    /// legitimate established connection.  Returns `true` if an entry
    /// was evicted (leaving a tombstone).
    fn evict_one(&mut self) -> bool {
        let mut expired_idx: Option<usize> = None;
        let mut oldest_new_idx: Option<usize> = None;
        let mut oldest_new_tick: u64 = u64::MAX;

        for (idx, slot) in self.entries.iter().enumerate() {
            if let Slot::Occupied(entry) = slot {
                if entry.is_expired() {
                    expired_idx = Some(idx);
                    break;
                }
                if entry.state == ConnTrackState::New && entry.created_tick <= oldest_new_tick {
                    oldest_new_tick = entry.created_tick;
                    oldest_new_idx = Some(idx);
                }
            }
        }

        let victim = expired_idx.or(oldest_new_idx);
        if let Some(idx) = victim {
            self.entries[idx] = Slot::Tombstone;
            self.count = self.count.saturating_sub(1);
            self.tombstones = self.tombstones.saturating_add(1);
            self.total_evicted = self.total_evicted.saturating_add(1);
            return true;
        }
        false
    }

    /// Update TCP-specific connection state based on flags.
    ///
    /// # Security
    ///
    /// TCP flags here are attacker-controlled.  This tracker does not
    /// carry per-direction send/receive windows, so a full RFC 5961
    /// sequence-validated RST/SYN check is out of scope (it would
    /// require window state not present in [`ConnTrackEntry`]).  As a
    /// lightweight mitigation we apply a *contextual* RST filter
    /// instead of honouring every RST: a RST is only allowed to tear
    /// down a flow when it is plausible for the current sub-state.
    /// This rejects the classic blind off-path RST shapes while
    /// preserving legitimate teardown (RST-ACK refusals, RST on a
    /// live flow).  The `New -> Established` promotion likewise
    /// already requires the ACK flag (see the `SynRecv` arm below).
    fn apply_tcp_state(entry: &mut ConnTrackEntry, is_reply: bool, tcp_flags: u16) {
        // TCP flag constants (mirroring tcp.rs)
        const FIN: u16 = 0x01;
        const SYN: u16 = 0x02;
        const RST: u16 = 0x04;
        const ACK: u16 = 0x10;

        if tcp_flags & RST != 0 {
            if Self::rst_in_context(entry.tcp_state, is_reply, tcp_flags & ACK != 0) {
                entry.tcp_state = TcpConnState::Closed;
                entry.state = ConnTrackState::Invalid;
                entry.timeout = 10; // Quick expiry
            }
            // Out-of-context RST: ignore it and keep the existing
            // state/timeout so a forged segment cannot drop the flow.
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

    /// Decide whether a RST is plausible enough to act on, given the
    /// current TCP sub-state, the packet direction, and whether the
    /// segment also carries ACK.
    ///
    /// This is a coarse contextual filter (not a sequence check): it
    /// drops the off-path shapes that have no legitimate counterpart
    /// while letting real teardown through.
    ///
    /// * `SynSent` — only a *reply* RST-ACK (a peer refusing the
    ///   connection) is honoured.  A RST from the initiator side, or
    ///   any bare RST without ACK, before a handshake exists is
    ///   treated as forged and ignored.
    /// * `Closed` — the flow is already torn down; a further RST is
    ///   redundant and ignored (prevents timeout churn).
    /// * any other established/closing sub-state — a RST is accepted,
    ///   matching normal abortive-close behaviour.
    const fn rst_in_context(state: TcpConnState, is_reply: bool, has_ack: bool) -> bool {
        match state {
            TcpConnState::SynSent => is_reply && has_ack,
            TcpConnState::Closed => false,
            _ => true,
        }
    }

    /// Remove a connection entry by 5-tuple.
    ///
    /// The freed slot becomes a [`Slot::Tombstone`] so that any entry
    /// inserted later in the same probe chain stays reachable.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching entry exists.
    pub fn remove(&mut self, tuple: &ConnTrackTuple) -> Result<()> {
        let start = tuple.hash();
        for i in 0..CONNTRACK_TABLE_SIZE {
            let idx = (start + i) % CONNTRACK_TABLE_SIZE;
            match &self.entries[idx] {
                Slot::Occupied(entry)
                    if entry.active && (entry.original == *tuple || entry.reply == *tuple) =>
                {
                    self.entries[idx] = Slot::Tombstone;
                    self.count = self.count.saturating_sub(1);
                    self.tombstones = self.tombstones.saturating_add(1);
                    return Ok(());
                }
                Slot::Empty => return Err(Error::NotFound),
                _ => {}
            }
        }
        Err(Error::NotFound)
    }

    /// Remove all entries, resetting the table to empty.
    ///
    /// A full reset clears every slot — including tombstones — so the
    /// chain-preservation invariant is trivially restored.
    pub fn flush(&mut self) {
        for slot in self.entries.iter_mut() {
            *slot = Slot::Empty;
        }
        self.count = 0;
        self.tombstones = 0;
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
        for entry in self.entries.iter().filter_map(Slot::entry) {
            if entry.active {
                f(entry);
            }
        }
    }

    /// Return the number of entries in a given state.
    pub fn count_by_state(&self, state: ConnTrackState) -> usize {
        let mut n = 0;
        for entry in self.entries.iter().filter_map(Slot::entry) {
            if entry.active && entry.state == state {
                n += 1;
            }
        }
        n
    }

    /// Perform a full GC sweep, removing all expired entries.
    ///
    /// Unlike [`Self::tick`], which decrements timeouts and
    /// removes entries that drop to zero, `gc_sweep` scans for
    /// entries that are already marked expired or inactive and
    /// reclaims their slots.  This is useful for periodic
    /// housekeeping independent of the tick rate.
    ///
    /// Returns the number of entries reclaimed.
    ///
    /// Reclaimed slots become tombstones, preserving probe chains.
    pub fn gc_sweep(&mut self) -> usize {
        let mut reclaimed = 0;
        for slot in self.entries.iter_mut() {
            if let Slot::Occupied(entry) = slot {
                if !entry.active || entry.is_expired() {
                    *slot = Slot::Tombstone;
                    self.count = self.count.saturating_sub(1);
                    self.tombstones = self.tombstones.saturating_add(1);
                    self.total_expired = self.total_expired.saturating_add(1);
                    reclaimed += 1;
                }
            }
        }
        reclaimed
    }

    /// Perform a targeted GC sweep, removing entries in a specific
    /// state that have exceeded a given age threshold.
    ///
    /// Returns the number of entries removed.  Removed slots become
    /// tombstones, preserving probe chains.
    pub fn gc_sweep_by_state(&mut self, state: ConnTrackState, max_age: u64) -> usize {
        let threshold = self.current_tick.saturating_sub(max_age);
        let mut removed = 0;
        for slot in self.entries.iter_mut() {
            if let Slot::Occupied(entry) = slot {
                if entry.active && entry.state == state && entry.created_tick < threshold {
                    *slot = Slot::Tombstone;
                    self.count = self.count.saturating_sub(1);
                    self.tombstones = self.tombstones.saturating_add(1);
                    self.total_expired = self.total_expired.saturating_add(1);
                    removed += 1;
                }
            }
        }
        removed
    }

    /// Apply a custom timeout configuration when refreshing an
    /// entry.
    ///
    /// Looks up the entry matching `tuple` and sets its timeout
    /// according to the provided [`ConnTrackTimeouts`] table rather
    /// than the compiled-in defaults.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching entry exists.
    pub fn refresh_with_timeouts(
        &mut self,
        tuple: &ConnTrackTuple,
        timeouts: &ConnTrackTimeouts,
    ) -> Result<()> {
        match self.lookup_mut(tuple) {
            Some((entry, _)) => {
                entry.timeout = timeouts.timeout_for(entry.original.protocol, entry.state);
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }
}

// =========================================================================
// NatType — SNAT / DNAT classification
// =========================================================================

/// Type of NAT applied to a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NatType {
    /// No NAT is applied.
    #[default]
    None,
    /// Source NAT — rewrite the source address/port of outgoing
    /// packets and the destination of returning packets.
    Snat,
    /// Destination NAT — rewrite the destination address/port of
    /// incoming packets and the source of returning packets.
    Dnat,
}

// =========================================================================
// NatBinding — per-connection NAT translation
// =========================================================================

/// NAT binding attached to a conntrack entry.
///
/// Stores the rewritten address and port so that packets in both
/// the original and reply directions can be translated correctly.
///
/// For SNAT the binding records the translated source; for DNAT
/// the binding records the translated destination.
#[derive(Debug, Clone, Copy)]
pub struct NatBinding {
    /// Type of NAT.
    pub nat_type: NatType,
    /// Rewritten IPv4 address.
    pub rewrite_ip: [u8; 4],
    /// Rewritten port (0 means port is unchanged).
    pub rewrite_port: u16,
    /// Original IPv4 address before translation.
    pub original_ip: [u8; 4],
    /// Original port before translation.
    pub original_port: u16,
    /// Number of packets translated.
    pub translated_packets: u64,
}

impl NatBinding {
    /// A binding with no translation.
    pub const fn none() -> Self {
        Self {
            nat_type: NatType::None,
            rewrite_ip: [0; 4],
            rewrite_port: 0,
            original_ip: [0; 4],
            original_port: 0,
            translated_packets: 0,
        }
    }

    /// Create a SNAT binding.
    ///
    /// Records that the original source address/port should be
    /// rewritten to `new_ip`/`new_port` on outgoing packets, and
    /// the reverse translation applied on reply packets.
    pub const fn snat(
        original_ip: [u8; 4],
        original_port: u16,
        new_ip: [u8; 4],
        new_port: u16,
    ) -> Self {
        Self {
            nat_type: NatType::Snat,
            rewrite_ip: new_ip,
            rewrite_port: new_port,
            original_ip,
            original_port,
            translated_packets: 0,
        }
    }

    /// Create a DNAT binding.
    ///
    /// Records that the original destination address/port should be
    /// rewritten to `new_ip`/`new_port` on incoming packets, and
    /// the reverse translation applied on reply packets.
    pub const fn dnat(
        original_ip: [u8; 4],
        original_port: u16,
        new_ip: [u8; 4],
        new_port: u16,
    ) -> Self {
        Self {
            nat_type: NatType::Dnat,
            rewrite_ip: new_ip,
            rewrite_port: new_port,
            original_ip,
            original_port,
            translated_packets: 0,
        }
    }

    /// Return whether this binding performs any translation.
    pub const fn is_active(&self) -> bool {
        !matches!(self.nat_type, NatType::None)
    }

    /// Apply the NAT translation to a mutable 5-tuple.
    ///
    /// For SNAT: rewrites `tuple.src_ip` and `tuple.src_port`.
    /// For DNAT: rewrites `tuple.dst_ip` and `tuple.dst_port`.
    ///
    /// Returns `true` if a translation was applied.
    pub fn translate(&mut self, tuple: &mut ConnTrackTuple) -> bool {
        match self.nat_type {
            NatType::None => false,
            NatType::Snat => {
                tuple.src_ip = self.rewrite_ip;
                if self.rewrite_port != 0 {
                    tuple.src_port = self.rewrite_port;
                }
                self.translated_packets = self.translated_packets.wrapping_add(1);
                true
            }
            NatType::Dnat => {
                tuple.dst_ip = self.rewrite_ip;
                if self.rewrite_port != 0 {
                    tuple.dst_port = self.rewrite_port;
                }
                self.translated_packets = self.translated_packets.wrapping_add(1);
                true
            }
        }
    }

    /// Apply the reverse NAT translation to a reply-direction
    /// tuple.
    ///
    /// For SNAT: rewrites `tuple.dst_ip` and `tuple.dst_port`
    /// back to the original source.
    /// For DNAT: rewrites `tuple.src_ip` and `tuple.src_port`
    /// back to the original destination.
    ///
    /// Returns `true` if a translation was applied.
    pub fn reverse_translate(&mut self, tuple: &mut ConnTrackTuple) -> bool {
        match self.nat_type {
            NatType::None => false,
            NatType::Snat => {
                tuple.dst_ip = self.original_ip;
                if self.original_port != 0 {
                    tuple.dst_port = self.original_port;
                }
                self.translated_packets = self.translated_packets.wrapping_add(1);
                true
            }
            NatType::Dnat => {
                tuple.src_ip = self.original_ip;
                if self.original_port != 0 {
                    tuple.src_port = self.original_port;
                }
                self.translated_packets = self.translated_packets.wrapping_add(1);
                true
            }
        }
    }
}

// =========================================================================
// ConnTrackTimeouts — configurable per-protocol timeouts
// =========================================================================

/// Per-protocol timeout configuration for connection tracking.
///
/// Allows the administrator to override the compiled-in defaults
/// for each protocol and state.
#[derive(Debug, Clone, Copy)]
pub struct ConnTrackTimeouts {
    /// Timeout for new TCP connections (SYN sent, awaiting
    /// SYN-ACK).
    pub tcp_new: u64,
    /// Timeout for established TCP connections.
    pub tcp_established: u64,
    /// Timeout for TCP connections in FIN-WAIT / CLOSE-WAIT.
    pub tcp_close: u64,
    /// Timeout for new/established UDP flows.
    pub udp_timeout: u64,
    /// Timeout for ICMP flows.
    pub icmp_timeout: u64,
    /// Default timeout for protocols not otherwise configured.
    pub generic_timeout: u64,
}

impl Default for ConnTrackTimeouts {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnTrackTimeouts {
    /// Create timeout configuration using compiled-in defaults.
    pub const fn new() -> Self {
        Self {
            tcp_new: NEW_TIMEOUT,
            tcp_established: TCP_ESTABLISHED_TIMEOUT,
            tcp_close: 120,
            udp_timeout: UDP_ESTABLISHED_TIMEOUT,
            icmp_timeout: ICMP_TIMEOUT,
            generic_timeout: NEW_TIMEOUT,
        }
    }

    /// Return the timeout for a protocol in a given conntrack state.
    pub const fn timeout_for(&self, protocol: ConnTrackProtocol, state: ConnTrackState) -> u64 {
        match protocol {
            ConnTrackProtocol::Tcp => match state {
                ConnTrackState::New => self.tcp_new,
                ConnTrackState::Established => self.tcp_established,
                ConnTrackState::Related => self.tcp_established,
                ConnTrackState::Invalid => self.tcp_close,
            },
            ConnTrackProtocol::Udp => self.udp_timeout,
            ConnTrackProtocol::Icmp => self.icmp_timeout,
            ConnTrackProtocol::Other(_) => self.generic_timeout,
        }
    }
}

// =========================================================================
// NatTable — system-wide NAT binding table
// =========================================================================

/// Maximum number of NAT bindings in the system.
const NAT_TABLE_SIZE: usize = 128;

/// A single NAT table entry associating a conntrack 5-tuple with
/// a NAT binding.
#[derive(Debug, Clone, Copy)]
struct NatEntry {
    /// Whether this slot is active.
    active: bool,
    /// The original 5-tuple of the tracked connection.
    original: ConnTrackTuple,
    /// The NAT binding applied to this connection.
    binding: NatBinding,
}

impl NatEntry {
    /// An empty entry.
    const EMPTY: Self = Self {
        active: false,
        original: ConnTrackTuple::new([0; 4], [0; 4], 0, 0, ConnTrackProtocol::Tcp),
        binding: NatBinding::none(),
    };
}

/// System-wide NAT binding table.
///
/// Maps conntrack 5-tuples to their NAT bindings (SNAT or DNAT).
/// Used by the forwarding path to translate packet headers.
pub struct NatTable {
    /// NAT entries.
    entries: [NatEntry; NAT_TABLE_SIZE],
    /// Number of active bindings.
    count: usize,
}

impl Default for NatTable {
    fn default() -> Self {
        Self::new()
    }
}

impl NatTable {
    /// Create an empty NAT table.
    pub const fn new() -> Self {
        Self {
            entries: [NatEntry::EMPTY; NAT_TABLE_SIZE],
            count: 0,
        }
    }

    /// Return the number of active NAT bindings.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Add a NAT binding for a connection.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    /// Returns [`Error::AlreadyExists`] if a binding already
    /// exists for this tuple.
    pub fn add(&mut self, original: &ConnTrackTuple, binding: NatBinding) -> Result<()> {
        // Check for duplicate
        for entry in self.entries.iter() {
            if entry.active && entry.original == *original {
                return Err(Error::AlreadyExists);
            }
        }
        // Find a free slot
        for entry in self.entries.iter_mut() {
            if !entry.active {
                entry.active = true;
                entry.original = *original;
                entry.binding = binding;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up the NAT binding for a connection.
    pub fn lookup(&self, original: &ConnTrackTuple) -> Option<&NatBinding> {
        for entry in self.entries.iter() {
            if entry.active && entry.original == *original {
                return Some(&entry.binding);
            }
        }
        None
    }

    /// Look up the NAT binding for a connection (mutable).
    pub fn lookup_mut(&mut self, original: &ConnTrackTuple) -> Option<&mut NatBinding> {
        for entry in self.entries.iter_mut() {
            if entry.active && entry.original == *original {
                return Some(&mut entry.binding);
            }
        }
        None
    }

    /// Remove the NAT binding for a connection.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no binding exists.
    pub fn remove(&mut self, original: &ConnTrackTuple) -> Result<()> {
        for entry in self.entries.iter_mut() {
            if entry.active && entry.original == *original {
                entry.active = false;
                self.count = self.count.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Remove all NAT bindings associated with entries not present
    /// in the given conntrack table.
    ///
    /// Returns the number of stale bindings removed.
    pub fn gc_stale(&mut self, ct_table: &ConnTrackTable) -> usize {
        let mut removed = 0;
        for entry in self.entries.iter_mut() {
            if entry.active && ct_table.lookup(&entry.original).is_none() {
                entry.active = false;
                self.count = self.count.saturating_sub(1);
                removed += 1;
            }
        }
        removed
    }

    /// Remove all bindings.
    pub fn flush(&mut self) {
        for entry in self.entries.iter_mut() {
            entry.active = false;
        }
        self.count = 0;
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

impl Default for ExpectationTable {
    fn default() -> Self {
        Self::new()
    }
}

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

/// Top-level connection tracker combining the connection table,
/// expectation table, NAT table, and configurable timeouts.
///
/// This is the primary API for the firewall / network stack to
/// classify packets by connection state and perform NAT.
pub struct ConnTracker {
    /// Connection tracking table.
    pub table: ConnTrackTable,
    /// Expectation table for related connections.
    pub expectations: ExpectationTable,
    /// NAT binding table.
    pub nat: NatTable,
    /// Per-protocol timeout configuration.
    pub timeouts: ConnTrackTimeouts,
    /// Whether connection tracking is enabled.
    enabled: bool,
}

impl Default for ConnTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnTracker {
    /// Create a new connection tracker (enabled by default).
    pub const fn new() -> Self {
        Self {
            table: ConnTrackTable::new(),
            expectations: ExpectationTable::new(),
            nat: NatTable::new(),
            timeouts: ConnTrackTimeouts::new(),
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

        // Check expectations first -- a matching expectation means
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

    /// Process a packet with NAT translation.
    ///
    /// First classifies the packet through connection tracking,
    /// then applies any configured NAT binding.  The `tuple` is
    /// modified in place if a NAT translation is applied.
    ///
    /// Returns a pair of (conntrack state, whether NAT was applied).
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the conntrack table is
    /// full.
    pub fn process_with_nat(
        &mut self,
        tuple: &mut ConnTrackTuple,
        packet_len: u64,
        tcp_flags: u16,
    ) -> Result<(ConnTrackState, bool)> {
        // Save original tuple for NAT lookup before potential
        // modification
        let orig = *tuple;
        let state = self.process(&orig, packet_len, tcp_flags)?;

        // Look for an existing NAT binding
        let (_, is_reply) = self
            .table
            .lookup(&orig)
            .map(|(_, r)| ((), r))
            .unwrap_or(((), false));

        let natted = if let Some(binding) = self.nat.lookup_mut(&orig) {
            if is_reply {
                binding.reverse_translate(tuple)
            } else {
                binding.translate(tuple)
            }
        } else {
            false
        };

        Ok((state, natted))
    }

    /// Add a SNAT binding for a tracked connection.
    ///
    /// Rewrites the source address/port of packets in the original
    /// direction and the destination of reply packets.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the connection is not tracked.
    /// Returns [`Error::OutOfMemory`] if the NAT table is full.
    /// Returns [`Error::AlreadyExists`] if a NAT binding already
    /// exists for this connection.
    pub fn add_snat(
        &mut self,
        original: &ConnTrackTuple,
        new_ip: [u8; 4],
        new_port: u16,
    ) -> Result<()> {
        // Verify the connection is tracked
        if self.table.lookup(original).is_none() {
            return Err(Error::NotFound);
        }
        let binding = NatBinding::snat(original.src_ip, original.src_port, new_ip, new_port);
        self.nat.add(original, binding)
    }

    /// Add a DNAT binding for a tracked connection.
    ///
    /// Rewrites the destination address/port of packets in the
    /// original direction and the source of reply packets.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the connection is not tracked.
    /// Returns [`Error::OutOfMemory`] if the NAT table is full.
    /// Returns [`Error::AlreadyExists`] if a NAT binding already
    /// exists for this connection.
    pub fn add_dnat(
        &mut self,
        original: &ConnTrackTuple,
        new_ip: [u8; 4],
        new_port: u16,
    ) -> Result<()> {
        // Verify the connection is tracked
        if self.table.lookup(original).is_none() {
            return Err(Error::NotFound);
        }
        let binding = NatBinding::dnat(original.dst_ip, original.dst_port, new_ip, new_port);
        self.nat.add(original, binding)
    }

    /// Advance the tick counter on all tables and expire stale
    /// entries.
    pub fn tick(&mut self, ticks: u64) {
        self.table.tick(ticks);
        self.expectations.tick(ticks);
    }

    /// Perform a full garbage collection sweep.
    ///
    /// Removes expired conntrack entries, then cleans up stale NAT
    /// bindings that no longer have a corresponding conntrack entry.
    ///
    /// Returns `(conntrack_removed, nat_removed)`.
    pub fn gc_sweep(&mut self) -> (usize, usize) {
        let ct_removed = self.table.gc_sweep();
        let nat_removed = self.nat.gc_stale(&self.table);
        (ct_removed, nat_removed)
    }

    /// Flush all connections, expectations, and NAT bindings.
    pub fn flush(&mut self) {
        self.table.flush();
        self.expectations.flush();
        self.nat.flush();
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

        // Expect the FTP active-mode data connection 10.0.0.2:20 -> 10.0.0.1:50000.
        // An expectation describes where the anticipated connection is *going*:
        // the client's advertised data port (50000), with the server's source
        // wildcarded. Port 20 is the server's source port, not the key.
        ct.expectations
            .add(
                [0; 4],
                [10, 0, 0, 1],
                50000,
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
