// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Virtual Ethernet (veth) pair devices for the ONCRIX kernel.
//!
//! A veth pair creates two connected virtual Ethernet endpoints:
//! any packet transmitted on one end is immediately delivered to
//! the receive buffer of the other end, like a cross-over cable.
//! Veth pairs are the primary mechanism for connecting network
//! namespaces to each other and to the host network stack.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────┐  tx ──→ rx  ┌──────────┐
//! │ VethEnd  │             │ VethEnd  │
//! │  (end_a) │  rx ←── tx  │  (end_b) │
//! └──────────┘             └──────────┘
//! ```
//!
//! Each [`VethEnd`] has independent:
//! - 32-slot ring buffer for packet reception (4 KiB per packet)
//! - MAC address and link state (up/down)
//! - Per-end traffic statistics ([`VethStats`])
//! - MTU configuration (default 1500)
//! - Promiscuous mode flag
//!
//! The [`VethPair`] binds two ends together.  The [`VethRegistry`]
//! manages up to 32 pairs system-wide.

use oncrix_lib::{Error, Result};

// =========================================================================
// Constants
// =========================================================================

/// Maximum transmission unit (default).
const DEFAULT_MTU: u16 = 1500;

/// Maximum packet size in bytes (jumbo-frame capable buffer).
const PACKET_BUF_SIZE: usize = 4096;

/// Number of packet slots in each end's receive ring buffer.
const RING_SIZE: usize = 32;

/// Maximum number of veth pairs in the system registry.
const MAX_PAIRS: usize = 32;

// =========================================================================
// VethStats
// =========================================================================

/// Per-end traffic statistics for a virtual Ethernet device.
///
/// All counters are monotonically increasing and wrap on overflow.
#[derive(Debug, Clone, Copy, Default)]
pub struct VethStats {
    /// Number of packets successfully transmitted to the peer.
    pub tx_packets: u64,
    /// Number of packets received from the peer.
    pub rx_packets: u64,
    /// Total bytes transmitted (excluding any framing).
    pub tx_bytes: u64,
    /// Total bytes received (excluding any framing).
    pub rx_bytes: u64,
    /// Number of packets dropped on the transmit path (peer
    /// receive ring full).
    pub tx_dropped: u64,
    /// Number of packets dropped on the receive path (local ring
    /// full, should not happen in normal operation).
    pub rx_dropped: u64,
}

impl VethStats {
    /// Create a zeroed statistics block.
    pub const fn new() -> Self {
        Self {
            tx_packets: 0,
            rx_packets: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            tx_dropped: 0,
            rx_dropped: 0,
        }
    }

    /// Reset all counters to zero.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

// =========================================================================
// LinkState
// =========================================================================

/// Link state of a virtual Ethernet end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// The link is up and can transmit/receive packets.
    Up,
    /// The link is down; all packets are silently dropped.
    Down,
}

// =========================================================================
// PacketSlot
// =========================================================================

/// A single packet slot in the receive ring buffer.
#[derive(Clone, Copy)]
struct PacketSlot {
    /// Raw packet data.
    data: [u8; PACKET_BUF_SIZE],
    /// Number of valid bytes in `data`.
    len: usize,
}

impl PacketSlot {
    /// An empty packet slot.
    const EMPTY: Self = Self {
        data: [0u8; PACKET_BUF_SIZE],
        len: 0,
    };
}

// =========================================================================
// VethEnd
// =========================================================================

/// One side of a virtual Ethernet pair.
///
/// Each end has its own MAC address, link state, receive ring
/// buffer, and traffic statistics.  Transmission is always
/// directed at the peer end (handled by [`VethPair`]).
pub struct VethEnd {
    /// MAC address of this end.
    mac: [u8; 6],
    /// Current link state.
    link: LinkState,
    /// Maximum transmission unit in bytes.
    mtu: u16,
    /// Whether promiscuous mode is enabled.
    promiscuous: bool,
    /// Receive ring buffer.
    rx_ring: [PacketSlot; RING_SIZE],
    /// Write index (next slot to write into).
    rx_head: usize,
    /// Read index (next slot to read from).
    rx_tail: usize,
    /// Number of occupied slots in the ring.
    rx_count: usize,
    /// Per-end traffic statistics.
    pub stats: VethStats,
}

impl VethEnd {
    /// Create a new veth end with the given MAC address.
    const fn new(mac: [u8; 6]) -> Self {
        Self {
            mac,
            link: LinkState::Down,
            mtu: DEFAULT_MTU,
            promiscuous: false,
            rx_ring: [PacketSlot::EMPTY; RING_SIZE],
            rx_head: 0,
            rx_tail: 0,
            rx_count: 0,
            stats: VethStats::new(),
        }
    }

    /// Return the MAC address of this end.
    pub const fn mac(&self) -> &[u8; 6] {
        &self.mac
    }

    /// Return the current link state.
    pub const fn link_state(&self) -> LinkState {
        self.link
    }

    /// Return the current MTU.
    pub const fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Return whether promiscuous mode is enabled.
    pub const fn is_promiscuous(&self) -> bool {
        self.promiscuous
    }

    /// Set the MTU.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `mtu` is zero or
    /// larger than [`PACKET_BUF_SIZE`].
    pub fn set_mtu(&mut self, mtu: u16) -> Result<()> {
        if mtu == 0 || mtu as usize > PACKET_BUF_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.mtu = mtu;
        Ok(())
    }

    /// Enable or disable promiscuous mode.
    pub fn set_promiscuous(&mut self, enabled: bool) {
        self.promiscuous = enabled;
    }

    /// Enqueue a packet into this end's receive ring.
    ///
    /// Returns `true` if the packet was enqueued, `false` if the
    /// ring is full (packet dropped).
    fn enqueue_rx(&mut self, packet: &[u8]) -> bool {
        if self.rx_count >= RING_SIZE {
            self.stats.rx_dropped += 1;
            return false;
        }
        let slot = &mut self.rx_ring[self.rx_head];
        let len = if packet.len() < PACKET_BUF_SIZE {
            packet.len()
        } else {
            PACKET_BUF_SIZE
        };
        slot.data[..len].copy_from_slice(&packet[..len]);
        slot.len = len;
        self.rx_head = (self.rx_head + 1) % RING_SIZE;
        self.rx_count += 1;
        self.stats.rx_packets += 1;
        self.stats.rx_bytes += len as u64;
        true
    }

    /// Dequeue a packet from this end's receive ring into `buf`.
    ///
    /// Returns the number of bytes copied, or zero if the ring is
    /// empty.
    fn dequeue_rx(&mut self, buf: &mut [u8]) -> usize {
        if self.rx_count == 0 {
            return 0;
        }
        let slot = &self.rx_ring[self.rx_tail];
        let len = if slot.len < buf.len() {
            slot.len
        } else {
            buf.len()
        };
        buf[..len].copy_from_slice(&slot.data[..len]);
        self.rx_tail = (self.rx_tail + 1) % RING_SIZE;
        self.rx_count -= 1;
        len
    }

    /// Return the number of packets waiting in the receive ring.
    pub const fn rx_pending(&self) -> usize {
        self.rx_count
    }
}

// =========================================================================
// VethPair
// =========================================================================

/// A pair of connected virtual Ethernet ends.
///
/// Packets transmitted on `end_a` are delivered to `end_b`'s
/// receive ring, and vice versa.
pub struct VethPair {
    /// First end of the pair.
    pub end_a: VethEnd,
    /// Second end of the pair.
    pub end_b: VethEnd,
    /// Unique pair identifier (assigned by [`VethRegistry`]).
    id: u32,
    /// Whether this pair slot is in use.
    in_use: bool,
}

impl VethPair {
    /// Create a new veth pair with the given ID and MAC addresses.
    const fn new(id: u32, mac_a: [u8; 6], mac_b: [u8; 6]) -> Self {
        Self {
            end_a: VethEnd::new(mac_a),
            end_b: VethEnd::new(mac_b),
            id,
            in_use: false,
        }
    }

    /// An empty, unused pair slot.
    const EMPTY: Self = Self::new(0, [0; 6], [0; 6]);

    /// Return the pair identifier.
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Transmit a packet from end A to end B.
    ///
    /// The packet is enqueued in end B's receive ring.  If end A
    /// or end B is link-down, the packet is silently dropped.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the packet exceeds
    /// end A's MTU.
    fn xmit_a_to_b(&mut self, packet: &[u8]) -> Result<bool> {
        if packet.len() > self.end_a.mtu as usize {
            return Err(Error::InvalidArgument);
        }
        if self.end_a.link != LinkState::Up || self.end_b.link != LinkState::Up {
            self.end_a.stats.tx_dropped += 1;
            return Ok(false);
        }
        self.end_a.stats.tx_packets += 1;
        self.end_a.stats.tx_bytes += packet.len() as u64;
        let enqueued = self.end_b.enqueue_rx(packet);
        if !enqueued {
            self.end_a.stats.tx_dropped += 1;
        }
        Ok(enqueued)
    }

    /// Transmit a packet from end B to end A.
    ///
    /// The packet is enqueued in end A's receive ring.  If end A
    /// or end B is link-down, the packet is silently dropped.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the packet exceeds
    /// end B's MTU.
    fn xmit_b_to_a(&mut self, packet: &[u8]) -> Result<bool> {
        if packet.len() > self.end_b.mtu as usize {
            return Err(Error::InvalidArgument);
        }
        if self.end_a.link != LinkState::Up || self.end_b.link != LinkState::Up {
            self.end_b.stats.tx_dropped += 1;
            return Ok(false);
        }
        self.end_b.stats.tx_packets += 1;
        self.end_b.stats.tx_bytes += packet.len() as u64;
        let enqueued = self.end_a.enqueue_rx(packet);
        if !enqueued {
            self.end_b.stats.tx_dropped += 1;
        }
        Ok(enqueued)
    }
}

// =========================================================================
// VethSide
// =========================================================================

/// Identifies which side of a veth pair an operation targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VethSide {
    /// End A (first end).
    A,
    /// End B (second end).
    B,
}

// =========================================================================
// VethRegistry
// =========================================================================

/// System-wide registry of virtual Ethernet pairs.
///
/// Manages up to [`MAX_PAIRS`] (32) veth pairs.  Each pair is
/// identified by a monotonically increasing ID.
pub struct VethRegistry {
    /// Pair slots.
    pairs: [VethPair; MAX_PAIRS],
    /// Next pair ID to assign.
    next_id: u32,
}

impl Default for VethRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl VethRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            pairs: [VethPair::EMPTY; MAX_PAIRS],
            next_id: 1,
        }
    }

    /// Create a new veth pair with the given MAC addresses.
    ///
    /// Both ends start in the [`LinkState::Down`] state.
    /// Returns the pair ID on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn create_pair(&mut self, mac_a: [u8; 6], mac_b: [u8; 6]) -> Result<u32> {
        for i in 0..MAX_PAIRS {
            if !self.pairs[i].in_use {
                let id = self.next_id;
                self.next_id = self.next_id.wrapping_add(1);
                self.pairs[i] = VethPair::new(id, mac_a, mac_b);
                self.pairs[i].in_use = true;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Destroy a veth pair by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the pair does not exist.
    pub fn destroy_pair(&mut self, pair_id: u32) -> Result<()> {
        for i in 0..MAX_PAIRS {
            if self.pairs[i].in_use && self.pairs[i].id == pair_id {
                self.pairs[i].in_use = false;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Look up a pair by ID, returning a mutable reference.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the pair does not exist.
    pub fn find_pair(&mut self, pair_id: u32) -> Result<&mut VethPair> {
        for i in 0..MAX_PAIRS {
            if self.pairs[i].in_use && self.pairs[i].id == pair_id {
                return Ok(&mut self.pairs[i]);
            }
        }
        Err(Error::NotFound)
    }

    /// Find the peer side for a given pair and side.
    ///
    /// Given a pair ID and a side (A or B), returns a reference to
    /// the opposite end's statistics and link state, useful for
    /// diagnosing connectivity.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the pair does not exist.
    pub fn find_peer(&mut self, pair_id: u32, side: VethSide) -> Result<&mut VethEnd> {
        let pair = self.find_pair(pair_id)?;
        match side {
            VethSide::A => Ok(&mut pair.end_b),
            VethSide::B => Ok(&mut pair.end_a),
        }
    }

    /// Return the number of active pairs.
    pub fn active_count(&self) -> usize {
        let mut count = 0;
        for i in 0..MAX_PAIRS {
            if self.pairs[i].in_use {
                count += 1;
            }
        }
        count
    }
}

// =========================================================================
// Public API functions
// =========================================================================

/// Transmit a packet on one side of a veth pair.
///
/// The packet is delivered to the peer end's receive ring buffer.
/// If either end is link-down, the packet is silently dropped and
/// the tx_dropped counter is incremented.
///
/// Returns `true` if the packet was successfully enqueued on the
/// peer, `false` if it was dropped (peer ring full or link down).
///
/// # Errors
///
/// Returns [`Error::NotFound`] if the pair does not exist.
/// Returns [`Error::InvalidArgument`] if the packet exceeds the
/// sender's MTU.
pub fn veth_xmit(
    registry: &mut VethRegistry,
    pair_id: u32,
    side: VethSide,
    packet: &[u8],
) -> Result<bool> {
    let pair = registry.find_pair(pair_id)?;
    match side {
        VethSide::A => pair.xmit_a_to_b(packet),
        VethSide::B => pair.xmit_b_to_a(packet),
    }
}

/// Poll the receive buffer of one side of a veth pair.
///
/// Copies the next available packet into `buf` and returns the
/// number of bytes copied.  Returns zero if no packets are
/// available.
///
/// # Errors
///
/// Returns [`Error::NotFound`] if the pair does not exist.
pub fn veth_receive(
    registry: &mut VethRegistry,
    pair_id: u32,
    side: VethSide,
    buf: &mut [u8],
) -> Result<usize> {
    let pair = registry.find_pair(pair_id)?;
    let end = match side {
        VethSide::A => &mut pair.end_a,
        VethSide::B => &mut pair.end_b,
    };
    Ok(end.dequeue_rx(buf))
}

/// Set the link state of one side of a veth pair.
///
/// When the link is brought down, packets transmitted to this end
/// are silently dropped.
///
/// # Errors
///
/// Returns [`Error::NotFound`] if the pair does not exist.
pub fn veth_set_link(
    registry: &mut VethRegistry,
    pair_id: u32,
    side: VethSide,
    state: LinkState,
) -> Result<()> {
    let pair = registry.find_pair(pair_id)?;
    let end = match side {
        VethSide::A => &mut pair.end_a,
        VethSide::B => &mut pair.end_b,
    };
    end.link = state;
    Ok(())
}
