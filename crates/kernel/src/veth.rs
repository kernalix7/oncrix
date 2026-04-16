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
    /// Network namespace identifier (0 = initial namespace).
    ns_id: u32,
    /// Interface index within the namespace.
    ifindex: u32,
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
            ns_id: 0,
            ifindex: 0,
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

    /// Return the network namespace identifier for this end.
    pub const fn ns_id(&self) -> u32 {
        self.ns_id
    }

    /// Set the network namespace identifier for this end.
    ///
    /// Moving an end to a different namespace allows veth pairs to
    /// bridge traffic between network namespaces, which is the
    /// primary use case for container networking.
    pub fn set_ns_id(&mut self, ns_id: u32) {
        self.ns_id = ns_id;
    }

    /// Return the interface index within the namespace.
    pub const fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// Set the interface index within the namespace.
    pub fn set_ifindex(&mut self, ifindex: u32) {
        self.ifindex = ifindex;
    }

    /// Bring the link up.
    pub fn link_up(&mut self) {
        self.link = LinkState::Up;
    }

    /// Bring the link down and drain the receive ring.
    ///
    /// When a link goes down, all buffered packets are discarded.
    /// Returns the number of packets that were drained.
    pub fn link_down(&mut self) -> usize {
        self.link = LinkState::Down;
        let drained = self.rx_count;
        self.rx_head = 0;
        self.rx_tail = 0;
        self.rx_count = 0;
        drained
    }

    /// Set the MAC address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the MAC is all-zeros
    /// (reserved).
    pub fn set_mac(&mut self, mac: [u8; 6]) -> Result<()> {
        if mac == [0; 6] {
            return Err(Error::InvalidArgument);
        }
        self.mac = mac;
        Ok(())
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
// VethLinkEvent — link state change notification
// =========================================================================

/// Notification generated when a veth end's link state changes.
///
/// Higher layers (e.g. routing, ARP) subscribe to these events
/// to update their state when interfaces come up or go down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VethLinkEvent {
    /// Pair identifier.
    pub pair_id: u32,
    /// Which side of the pair changed.
    pub side: VethSide,
    /// New link state after the change.
    pub new_state: LinkState,
    /// Network namespace of the affected end.
    pub ns_id: u32,
}

// =========================================================================
// VethRegistry
// =========================================================================

/// Maximum number of pending link events in the event ring.
const MAX_LINK_EVENTS: usize = 64;

/// System-wide registry of virtual Ethernet pairs.
///
/// Manages up to [`MAX_PAIRS`] (32) veth pairs.  Each pair is
/// identified by a monotonically increasing ID.  The registry also
/// maintains a ring buffer of link state change events that can
/// be polled by upper layers.
pub struct VethRegistry {
    /// Pair slots.
    pairs: [VethPair; MAX_PAIRS],
    /// Next pair ID to assign.
    next_id: u32,
    /// Next interface index to assign.
    next_ifindex: u32,
    /// Pending link events ring buffer.
    events: [Option<VethLinkEvent>; MAX_LINK_EVENTS],
    /// Write head for events ring.
    event_head: usize,
    /// Read tail for events ring.
    event_tail: usize,
    /// Number of events pending.
    event_count: usize,
}

/// Compile-time initialiser for the event array.
const EMPTY_EVENT: Option<VethLinkEvent> = None;

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
            next_ifindex: 1,
            events: [EMPTY_EVENT; MAX_LINK_EVENTS],
            event_head: 0,
            event_tail: 0,
            event_count: 0,
        }
    }

    /// Create a new veth pair with the given MAC addresses.
    ///
    /// Both ends start in the [`LinkState::Down`] state and are
    /// assigned to the initial network namespace (ns_id = 0).
    /// Each end receives a unique interface index.
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
                // Assign unique interface indexes
                let if_a = self.next_ifindex;
                self.next_ifindex = self.next_ifindex.wrapping_add(1);
                let if_b = self.next_ifindex;
                self.next_ifindex = self.next_ifindex.wrapping_add(1);
                self.pairs[i].end_a.ifindex = if_a;
                self.pairs[i].end_b.ifindex = if_b;
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

    /// Move one side of a veth pair to a different network
    /// namespace.
    ///
    /// This is the core operation for container networking: one end
    /// stays in the host namespace, the other is moved into the
    /// container namespace.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the pair does not exist.
    pub fn set_ns(&mut self, pair_id: u32, side: VethSide, ns_id: u32) -> Result<()> {
        let pair = self.find_pair(pair_id)?;
        let end = match side {
            VethSide::A => &mut pair.end_a,
            VethSide::B => &mut pair.end_b,
        };
        end.ns_id = ns_id;
        Ok(())
    }

    /// Return the network namespace IDs for both ends of a pair.
    ///
    /// Returns `(ns_id_a, ns_id_b)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the pair does not exist.
    pub fn get_ns(&mut self, pair_id: u32) -> Result<(u32, u32)> {
        let pair = self.find_pair(pair_id)?;
        Ok((pair.end_a.ns_id, pair.end_b.ns_id))
    }

    /// Set the link state with event generation.
    ///
    /// Changes the link state and enqueues a [`VethLinkEvent`]
    /// for upper-layer notification.  If bringing the link down,
    /// the receive ring is drained.
    ///
    /// Returns the number of packets drained (0 for link-up).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the pair does not exist.
    pub fn set_link_with_event(
        &mut self,
        pair_id: u32,
        side: VethSide,
        state: LinkState,
    ) -> Result<usize> {
        let pair = self.find_pair(pair_id)?;
        let end = match side {
            VethSide::A => &mut pair.end_a,
            VethSide::B => &mut pair.end_b,
        };
        let drained = match state {
            LinkState::Up => {
                end.link_up();
                0
            }
            LinkState::Down => end.link_down(),
        };
        let ns_id = end.ns_id;
        self.push_event(VethLinkEvent {
            pair_id,
            side,
            new_state: state,
            ns_id,
        });
        Ok(drained)
    }

    /// Push a link event into the ring buffer.
    ///
    /// If the ring is full the oldest event is silently discarded.
    fn push_event(&mut self, event: VethLinkEvent) {
        if self.event_count >= MAX_LINK_EVENTS {
            // Overwrite oldest
            self.event_tail = (self.event_tail + 1) % MAX_LINK_EVENTS;
            self.event_count -= 1;
        }
        self.events[self.event_head] = Some(event);
        self.event_head = (self.event_head + 1) % MAX_LINK_EVENTS;
        self.event_count += 1;
    }

    /// Poll the next pending link event.
    ///
    /// Returns `None` if no events are pending.
    pub fn poll_event(&mut self) -> Option<VethLinkEvent> {
        if self.event_count == 0 {
            return None;
        }
        let event = self.events[self.event_tail].take();
        self.event_tail = (self.event_tail + 1) % MAX_LINK_EVENTS;
        self.event_count -= 1;
        event
    }

    /// Return the number of pending link events.
    pub const fn pending_events(&self) -> usize {
        self.event_count
    }

    /// Transmit multiple packets from one side to the peer.
    ///
    /// Each packet slice in `packets` is transmitted in order.
    /// Returns the number of packets successfully enqueued on the
    /// peer.  Stops early if any single packet exceeds the MTU.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the pair does not exist.
    /// Returns [`Error::InvalidArgument`] if any packet exceeds
    /// the MTU.
    pub fn bulk_xmit(&mut self, pair_id: u32, side: VethSide, packets: &[&[u8]]) -> Result<usize> {
        let pair = self.find_pair(pair_id)?;
        let mut sent = 0;
        for packet in packets {
            let result = match side {
                VethSide::A => pair.xmit_a_to_b(packet)?,
                VethSide::B => pair.xmit_b_to_a(packet)?,
            };
            if result {
                sent += 1;
            }
        }
        Ok(sent)
    }

    /// Set the MTU on one side of a veth pair.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the pair does not exist.
    /// Returns [`Error::InvalidArgument`] if the MTU is invalid.
    pub fn set_mtu(&mut self, pair_id: u32, side: VethSide, mtu: u16) -> Result<()> {
        let pair = self.find_pair(pair_id)?;
        let end = match side {
            VethSide::A => &mut pair.end_a,
            VethSide::B => &mut pair.end_b,
        };
        end.set_mtu(mtu)
    }

    /// Return statistics for one side of a veth pair.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the pair does not exist.
    pub fn get_stats(&mut self, pair_id: u32, side: VethSide) -> Result<VethStats> {
        let pair = self.find_pair(pair_id)?;
        let end = match side {
            VethSide::A => &pair.end_a,
            VethSide::B => &pair.end_b,
        };
        Ok(end.stats)
    }

    /// Reset statistics for one side of a veth pair.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the pair does not exist.
    pub fn reset_stats(&mut self, pair_id: u32, side: VethSide) -> Result<()> {
        let pair = self.find_pair(pair_id)?;
        let end = match side {
            VethSide::A => &mut pair.end_a,
            VethSide::B => &mut pair.end_b,
        };
        end.stats.reset();
        Ok(())
    }

    /// Find a pair by the interface index of either end.
    ///
    /// Returns the pair ID and which side matched.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no pair has the given
    /// ifindex.
    pub fn find_by_ifindex(&self, ifindex: u32) -> Result<(u32, VethSide)> {
        for pair in &self.pairs {
            if pair.in_use {
                if pair.end_a.ifindex == ifindex {
                    return Ok((pair.id, VethSide::A));
                }
                if pair.end_b.ifindex == ifindex {
                    return Ok((pair.id, VethSide::B));
                }
            }
        }
        Err(Error::NotFound)
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
