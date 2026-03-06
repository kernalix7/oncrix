// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Traffic Control (tc) subsystem for the ONCRIX kernel.
//!
//! Provides queuing disciplines (qdiscs), packet classification,
//! and traffic shaping inspired by the Linux `tc` infrastructure.
//!
//! # Architecture
//!
//! ```text
//! packet → [tc filter chain] → classify → [qdisc] → dequeue → NIC
//! ```
//!
//! Key components:
//!
//! - [`QdiscType`]: selectable queuing discipline algorithm
//!   (pfifo_fast, TBF, HTB, SFQ, FQ).
//! - [`TcAction`]: action returned by a filter or classifier.
//! - [`Qdisc`]: a queuing discipline instance that enqueues and
//!   dequeues packets according to its scheduling algorithm.
//! - [`PfifoFastQueue`]: three-band priority FIFO (the default
//!   Linux qdisc) with TOS-based band selection.
//! - [`TbfState`]: token bucket filter state for rate limiting.
//! - [`TcFilter`]: packet classifier matching on IP prefix and
//!   port range.
//! - [`TcRegistry`]: system-wide registry managing qdiscs and
//!   filters across up to [`MAX_TC_INTERFACES`] interfaces.
//!
//! Reference: Linux `net/sched/`, `include/uapi/linux/pkt_sched.h`.

use oncrix_lib::{Error, Result};

// =========================================================================
// Constants
// =========================================================================

/// Maximum number of interfaces with tc support.
const MAX_TC_INTERFACES: usize = 8;

/// Maximum number of qdiscs per interface.
const MAX_QDISCS_PER_IF: usize = 16;

/// Maximum number of filters per qdisc.
const MAX_FILTERS_PER_QDISC: usize = 16;

/// Maximum number of packets a qdisc can buffer.
const QDISC_QUEUE_LEN: usize = 128;

/// Maximum packet size in the qdisc queue (bytes).
const QDISC_PACKET_SIZE: usize = 2048;

/// Number of priority bands in pfifo_fast.
const PFIFO_BANDS: usize = 3;

/// Packets per band in pfifo_fast.
const PFIFO_BAND_LEN: usize = 43;

/// Default token bucket rate (tokens per tick).
const TBF_DEFAULT_RATE: u64 = 1000;

/// Default token bucket burst size.
const TBF_DEFAULT_BURST: u64 = 4096;

/// Default token bucket queue limit (bytes).
const TBF_DEFAULT_LIMIT: u64 = 65536;

// =========================================================================
// QdiscType
// =========================================================================

/// Queuing discipline algorithm selector.
///
/// Determines how packets are scheduled for transmission on an
/// interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QdiscType {
    /// Three-band priority FIFO (default Linux qdisc).
    ///
    /// Packets are classified into bands 0, 1, or 2 based on the
    /// IPv4 TOS field.  Band 0 (highest priority) is always
    /// drained first.
    #[default]
    PfifoFast,
    /// Token bucket filter -- simple rate limiter.
    ///
    /// Packets are enqueued only if tokens are available.
    /// Tokens replenish at a configured rate.
    Tbf,
    /// Hierarchical token bucket (stub).
    ///
    /// Provides class-based traffic shaping with borrowing.
    Htb,
    /// Stochastic fairness queueing (stub).
    ///
    /// Hashes flows into buckets served in round-robin order.
    Sfq,
    /// Fair queueing (stub).
    ///
    /// Per-flow queuing with pacing support.
    Fq,
}

// =========================================================================
// TcAction
// =========================================================================

/// Action returned by a tc filter or classifier.
///
/// Values align with the Linux `TC_ACT_*` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TcAction {
    /// Continue processing (accept the packet).
    #[default]
    Ok,
    /// Drop the packet (shot / policed).
    Shot,
    /// Packet has been consumed by the action (stolen).
    Stolen,
    /// Redirect the packet to another interface or qdisc.
    Redirect,
    /// Continue to the next filter in the chain.
    Pipe,
}

// =========================================================================
// QdiscPacket
// =========================================================================

/// A single packet stored inside a qdisc queue.
#[derive(Clone)]
struct QdiscPacket {
    /// Packet data.
    data: [u8; QDISC_PACKET_SIZE],
    /// Actual length of valid data.
    len: usize,
    /// Whether this slot is occupied.
    occupied: bool,
}

impl Default for QdiscPacket {
    fn default() -> Self {
        Self {
            data: [0u8; QDISC_PACKET_SIZE],
            len: 0,
            occupied: false,
        }
    }
}

// =========================================================================
// PfifoFastQueue
// =========================================================================

/// Three-band priority FIFO queue.
///
/// Band 0 is the highest priority and is always drained before
/// band 1, which in turn is drained before band 2.  Packets are
/// assigned to bands based on the IPv4 TOS byte using the standard
/// Linux `prio2band` mapping.
pub struct PfifoFastQueue {
    /// Per-band ring buffers.
    bands: [[QdiscPacket; PFIFO_BAND_LEN]; PFIFO_BANDS],
    /// Write index per band.
    head: [usize; PFIFO_BANDS],
    /// Read index per band.
    tail: [usize; PFIFO_BANDS],
    /// Number of packets in each band.
    count: [usize; PFIFO_BANDS],
}

impl Default for PfifoFastQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl PfifoFastQueue {
    /// Create an empty pfifo_fast queue.
    pub fn new() -> Self {
        Self {
            bands: core::array::from_fn(|_| core::array::from_fn(|_| QdiscPacket::default())),
            head: [0; PFIFO_BANDS],
            tail: [0; PFIFO_BANDS],
            count: [0; PFIFO_BANDS],
        }
    }

    /// Map a TOS byte to a priority band (0, 1, or 2).
    ///
    /// Uses the standard Linux mapping where:
    /// - TOS bits 7-5 → priority 0-7 → band 0/1/2.
    ///
    /// The simplified mapping:
    /// - priority 0 (best effort) → band 1
    /// - priority 1-3 (low-latency) → band 0
    /// - priority 4-7 (bulk) → band 2
    pub const fn tos_to_band(tos: u8) -> usize {
        let prio = (tos >> 5) & 0x07;
        match prio {
            0 => 1,     // best effort → band 1
            1..=3 => 0, // interactive → band 0 (highest)
            _ => 2,     // bulk → band 2 (lowest)
        }
    }

    /// Enqueue a packet into the band determined by its TOS value.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `data` is empty or too large.
    /// - [`Error::OutOfMemory`] if the target band is full.
    pub fn enqueue(&mut self, data: &[u8], tos: u8) -> Result<()> {
        if data.is_empty() || data.len() > QDISC_PACKET_SIZE {
            return Err(Error::InvalidArgument);
        }
        let band = Self::tos_to_band(tos);
        if self.count[band] >= PFIFO_BAND_LEN {
            return Err(Error::OutOfMemory);
        }
        let idx = self.head[band];
        self.bands[band][idx].data[..data.len()].copy_from_slice(data);
        self.bands[band][idx].len = data.len();
        self.bands[band][idx].occupied = true;
        self.head[band] = (idx + 1) % PFIFO_BAND_LEN;
        self.count[band] += 1;
        Ok(())
    }

    /// Dequeue the highest-priority packet.
    ///
    /// Drains band 0 first, then band 1, then band 2.
    ///
    /// Returns the packet data and its length, or
    /// [`Error::WouldBlock`] if all bands are empty.
    pub fn dequeue(&mut self, out: &mut [u8; QDISC_PACKET_SIZE]) -> Result<usize> {
        for band in 0..PFIFO_BANDS {
            if self.count[band] > 0 {
                let idx = self.tail[band];
                let pkt = &self.bands[band][idx];
                let len = pkt.len;
                out[..len].copy_from_slice(&pkt.data[..len]);
                self.bands[band][idx].occupied = false;
                self.tail[band] = (idx + 1) % PFIFO_BAND_LEN;
                self.count[band] -= 1;
                return Ok(len);
            }
        }
        Err(Error::WouldBlock)
    }

    /// Return the total number of enqueued packets across all
    /// bands.
    pub const fn total_len(&self) -> usize {
        self.count[0] + self.count[1] + self.count[2]
    }

    /// Return whether all bands are empty.
    pub const fn is_empty(&self) -> bool {
        self.total_len() == 0
    }
}

// =========================================================================
// TbfState
// =========================================================================

/// Token bucket filter state for rate limiting.
///
/// Tokens accumulate at a fixed rate up to a burst ceiling.  A
/// packet may be enqueued only if enough tokens are available to
/// cover its size; otherwise the packet is dropped.
pub struct TbfState {
    /// Current number of available tokens (in bytes).
    pub tokens: u64,
    /// Token replenishment rate (bytes per tick).
    pub rate: u64,
    /// Maximum token accumulation (burst size in bytes).
    pub burst: u64,
    /// Maximum queued data before tail-drop (bytes).
    pub limit: u64,
    /// Total queued bytes.
    pub queued_bytes: u64,
}

impl Default for TbfState {
    fn default() -> Self {
        Self::new()
    }
}

impl TbfState {
    /// Create a TBF state with default parameters.
    pub const fn new() -> Self {
        Self {
            tokens: TBF_DEFAULT_BURST,
            rate: TBF_DEFAULT_RATE,
            burst: TBF_DEFAULT_BURST,
            limit: TBF_DEFAULT_LIMIT,
            queued_bytes: 0,
        }
    }

    /// Create a TBF state with custom parameters.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if any parameter is zero.
    pub const fn with_params(rate: u64, burst: u64, limit: u64) -> Result<Self> {
        if rate == 0 || burst == 0 || limit == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            tokens: burst,
            rate,
            burst,
            limit,
            queued_bytes: 0,
        })
    }

    /// Replenish tokens (call once per scheduling tick).
    ///
    /// Adds `rate` tokens, capped at `burst`.
    pub fn tick(&mut self) {
        self.tokens = self.tokens.saturating_add(self.rate).min(self.burst);
    }

    /// Check whether a packet of `size` bytes can be admitted.
    ///
    /// Returns `true` if both the token bucket and queue limit
    /// allow the packet.
    pub const fn can_enqueue(&self, size: u64) -> bool {
        self.tokens >= size && (self.queued_bytes + size) <= self.limit
    }

    /// Consume tokens for an enqueued packet.
    pub fn consume(&mut self, size: u64) {
        self.tokens = self.tokens.saturating_sub(size);
        self.queued_bytes = self.queued_bytes.saturating_add(size);
    }

    /// Release quota when a packet is dequeued.
    pub fn release(&mut self, size: u64) {
        self.queued_bytes = self.queued_bytes.saturating_sub(size);
    }
}

// =========================================================================
// Qdisc
// =========================================================================

/// A queuing discipline instance.
///
/// Each qdisc manages a queue of packets and determines the order
/// in which they are dequeued for transmission.  The scheduling
/// algorithm is selected by [`QdiscType`].
pub struct Qdisc {
    /// Queuing discipline type.
    pub qdisc_type: QdiscType,
    /// Handle (unique identifier within the interface), encoded as
    /// `major:minor` in a `u32` (upper 16 bits = major).
    pub handle: u32,
    /// Parent handle (0 = root qdisc).
    pub parent: u32,
    /// Generic FIFO queue for simple qdisc types.
    queue: [QdiscPacket; QDISC_QUEUE_LEN],
    /// Write index into `queue`.
    head: usize,
    /// Read index into `queue`.
    tail: usize,
    /// Number of packets currently queued.
    count: usize,
    /// pfifo_fast state (used when `qdisc_type == PfifoFast`).
    pfifo: PfifoFastQueue,
    /// Token bucket filter state (used when `qdisc_type == Tbf`).
    tbf: TbfState,
    /// Total packets enqueued since creation.
    pub enqueued: u64,
    /// Total packets dequeued since creation.
    pub dequeued: u64,
    /// Total packets dropped since creation.
    pub dropped: u64,
    /// Whether this qdisc slot is active.
    active: bool,
}

impl Default for Qdisc {
    fn default() -> Self {
        Self::new(QdiscType::PfifoFast)
    }
}

impl Qdisc {
    /// Create a new qdisc of the specified type.
    pub fn new(qdisc_type: QdiscType) -> Self {
        Self {
            qdisc_type,
            handle: 0,
            parent: 0,
            queue: core::array::from_fn(|_| QdiscPacket::default()),
            head: 0,
            tail: 0,
            count: 0,
            pfifo: PfifoFastQueue::new(),
            tbf: TbfState::new(),
            enqueued: 0,
            dequeued: 0,
            dropped: 0,
            active: false,
        }
    }

    /// Enqueue a packet.
    ///
    /// Dispatches to the appropriate scheduling algorithm based on
    /// [`QdiscType`].
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `data` is empty or too large.
    /// - [`Error::OutOfMemory`] if the queue is full.
    pub fn enqueue(&mut self, data: &[u8], tos: u8) -> Result<()> {
        if data.is_empty() || data.len() > QDISC_PACKET_SIZE {
            return Err(Error::InvalidArgument);
        }
        let result = match self.qdisc_type {
            QdiscType::PfifoFast => self.pfifo.enqueue(data, tos),
            QdiscType::Tbf => self.enqueue_tbf(data),
            QdiscType::Htb | QdiscType::Sfq | QdiscType::Fq => self.enqueue_fifo(data),
        };
        match result {
            Ok(()) => {
                self.enqueued = self.enqueued.wrapping_add(1);
                Ok(())
            }
            Err(e) => {
                self.dropped = self.dropped.wrapping_add(1);
                Err(e)
            }
        }
    }

    /// Dequeue the next packet.
    ///
    /// Returns the packet data length written into `out`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WouldBlock`] if the queue is empty.
    pub fn dequeue(&mut self, out: &mut [u8; QDISC_PACKET_SIZE]) -> Result<usize> {
        let result = match self.qdisc_type {
            QdiscType::PfifoFast => self.pfifo.dequeue(out),
            QdiscType::Tbf => self.dequeue_tbf(out),
            QdiscType::Htb | QdiscType::Sfq | QdiscType::Fq => self.dequeue_fifo(out),
        };
        if let Ok(len) = result {
            self.dequeued = self.dequeued.wrapping_add(1);
            Ok(len)
        } else {
            result
        }
    }

    /// Replenish TBF tokens (call once per scheduling tick).
    pub fn tick(&mut self) {
        if self.qdisc_type == QdiscType::Tbf {
            self.tbf.tick();
        }
    }

    /// Return the number of packets currently queued.
    pub fn queued_len(&self) -> usize {
        match self.qdisc_type {
            QdiscType::PfifoFast => self.pfifo.total_len(),
            _ => self.count,
        }
    }

    /// Return whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queued_len() == 0
    }

    // -- private helpers --

    /// Enqueue into the generic FIFO (for HTB/SFQ/FQ stubs).
    fn enqueue_fifo(&mut self, data: &[u8]) -> Result<()> {
        if self.count >= QDISC_QUEUE_LEN {
            return Err(Error::OutOfMemory);
        }
        self.queue[self.head].data[..data.len()].copy_from_slice(data);
        self.queue[self.head].len = data.len();
        self.queue[self.head].occupied = true;
        self.head = (self.head + 1) % QDISC_QUEUE_LEN;
        self.count += 1;
        Ok(())
    }

    /// Dequeue from the generic FIFO.
    fn dequeue_fifo(&mut self, out: &mut [u8; QDISC_PACKET_SIZE]) -> Result<usize> {
        if self.count == 0 {
            return Err(Error::WouldBlock);
        }
        let pkt = &self.queue[self.tail];
        let len = pkt.len;
        out[..len].copy_from_slice(&pkt.data[..len]);
        self.queue[self.tail].occupied = false;
        self.tail = (self.tail + 1) % QDISC_QUEUE_LEN;
        self.count -= 1;
        Ok(len)
    }

    /// Enqueue with token bucket rate limiting.
    fn enqueue_tbf(&mut self, data: &[u8]) -> Result<()> {
        let size = data.len() as u64;
        if !self.tbf.can_enqueue(size) {
            return Err(Error::OutOfMemory);
        }
        self.tbf.consume(size);
        self.enqueue_fifo(data)
    }

    /// Dequeue from the TBF queue.
    fn dequeue_tbf(&mut self, out: &mut [u8; QDISC_PACKET_SIZE]) -> Result<usize> {
        let len = self.dequeue_fifo(out)?;
        self.tbf.release(len as u64);
        Ok(len)
    }
}

// =========================================================================
// TcFilter
// =========================================================================

/// A traffic control filter / classifier rule.
///
/// Matches packets based on source/destination IP prefix and port
/// range.  When a packet matches, the filter's [`TcAction`] is
/// returned.
pub struct TcFilter {
    /// Filter priority (lower value = higher priority).
    pub priority: u16,
    /// EtherType to match (0 = any, 0x0800 = IPv4).
    pub protocol: u16,
    /// Source IP address (network byte order).
    pub src_ip: u32,
    /// Source IP prefix length (0-32; 0 = match all).
    pub src_prefix_len: u8,
    /// Destination IP address (network byte order).
    pub dst_ip: u32,
    /// Destination IP prefix length (0-32; 0 = match all).
    pub dst_prefix_len: u8,
    /// Minimum source port (0 = no port match).
    pub src_port_min: u16,
    /// Maximum source port (0 = no port match).
    pub src_port_max: u16,
    /// Minimum destination port (0 = no port match).
    pub dst_port_min: u16,
    /// Maximum destination port (0 = no port match).
    pub dst_port_max: u16,
    /// Action to take when the filter matches.
    pub action: TcAction,
    /// Whether this filter slot is active.
    active: bool,
}

impl Default for TcFilter {
    fn default() -> Self {
        Self {
            priority: 0,
            protocol: 0,
            src_ip: 0,
            src_prefix_len: 0,
            dst_ip: 0,
            dst_prefix_len: 0,
            src_port_min: 0,
            src_port_max: 0,
            dst_port_min: 0,
            dst_port_max: 0,
            action: TcAction::Ok,
            active: false,
        }
    }
}

impl TcFilter {
    /// Create a new inactive filter.
    pub const fn new() -> Self {
        Self {
            priority: 0,
            protocol: 0,
            src_ip: 0,
            src_prefix_len: 0,
            dst_ip: 0,
            dst_prefix_len: 0,
            src_port_min: 0,
            src_port_max: 0,
            dst_port_min: 0,
            dst_port_max: 0,
            action: TcAction::Ok,
            active: false,
        }
    }

    /// Compute a subnet mask from a prefix length.
    const fn prefix_mask(prefix_len: u8) -> u32 {
        if prefix_len == 0 {
            0
        } else if prefix_len >= 32 {
            0xFFFF_FFFF
        } else {
            0xFFFF_FFFF << (32 - prefix_len)
        }
    }

    /// Check whether a packet matches this filter.
    ///
    /// `src_ip` and `dst_ip` are in network byte order.
    /// Port values of 0 in the filter mean "don't check ports".
    pub fn matches(&self, src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16) -> bool {
        if !self.active {
            return false;
        }
        // Source IP prefix match.
        if self.src_prefix_len > 0 {
            let mask = Self::prefix_mask(self.src_prefix_len);
            if (src_ip & mask) != (self.src_ip & mask) {
                return false;
            }
        }
        // Destination IP prefix match.
        if self.dst_prefix_len > 0 {
            let mask = Self::prefix_mask(self.dst_prefix_len);
            if (dst_ip & mask) != (self.dst_ip & mask) {
                return false;
            }
        }
        // Source port range.
        if (self.src_port_min > 0 || self.src_port_max > 0)
            && (src_port < self.src_port_min || src_port > self.src_port_max)
        {
            return false;
        }
        // Destination port range.
        if (self.dst_port_min > 0 || self.dst_port_max > 0)
            && (dst_port < self.dst_port_min || dst_port > self.dst_port_max)
        {
            return false;
        }
        true
    }
}

// =========================================================================
// TcQdiscSlot  (per-interface qdisc + filters)
// =========================================================================

/// Per-interface qdisc slot bundling a qdisc with its attached
/// filters.
struct TcQdiscSlot {
    /// The queuing discipline.
    qdisc: Qdisc,
    /// Attached filters.
    filters: [TcFilter; MAX_FILTERS_PER_QDISC],
    /// Number of active filters.
    filter_count: usize,
}

impl Default for TcQdiscSlot {
    fn default() -> Self {
        Self {
            qdisc: Qdisc::default(),
            filters: core::array::from_fn(|_| TcFilter::new()),
            filter_count: 0,
        }
    }
}

// =========================================================================
// TcInterface
// =========================================================================

/// Per-interface traffic control state.
struct TcInterface {
    /// Qdisc slots for this interface.
    qdiscs: [TcQdiscSlot; MAX_QDISCS_PER_IF],
    /// Number of active qdiscs.
    qdisc_count: usize,
}

impl Default for TcInterface {
    fn default() -> Self {
        Self {
            qdiscs: core::array::from_fn(|_| TcQdiscSlot::default()),
            qdisc_count: 0,
        }
    }
}

// =========================================================================
// TcRegistry
// =========================================================================

/// System-wide traffic control registry.
///
/// Manages up to [`MAX_QDISCS_PER_IF`] qdiscs per interface across
/// [`MAX_TC_INTERFACES`] interfaces, with up to
/// [`MAX_FILTERS_PER_QDISC`] filters per qdisc.
pub struct TcRegistry {
    /// Per-interface state.
    interfaces: [TcInterface; MAX_TC_INTERFACES],
}

impl Default for TcRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TcRegistry {
    /// Create an empty traffic control registry.
    pub fn new() -> Self {
        Self {
            interfaces: core::array::from_fn(|_| TcInterface::default()),
        }
    }

    /// Add a qdisc to an interface.
    ///
    /// Returns the qdisc slot index within the interface.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `ifindex` is out of range.
    /// - [`Error::OutOfMemory`] if the interface already has
    ///   [`MAX_QDISCS_PER_IF`] qdiscs.
    pub fn add_qdisc(
        &mut self,
        ifindex: usize,
        qdisc_type: QdiscType,
        handle: u32,
        parent: u32,
    ) -> Result<usize> {
        let iface = self
            .interfaces
            .get_mut(ifindex)
            .ok_or(Error::InvalidArgument)?;
        if iface.qdisc_count >= MAX_QDISCS_PER_IF {
            return Err(Error::OutOfMemory);
        }
        // Find the first inactive slot.
        let slot_idx = iface
            .qdiscs
            .iter()
            .position(|s| !s.qdisc.active)
            .ok_or(Error::OutOfMemory)?;
        let slot = &mut iface.qdiscs[slot_idx];
        slot.qdisc = Qdisc::new(qdisc_type);
        slot.qdisc.handle = handle;
        slot.qdisc.parent = parent;
        slot.qdisc.active = true;
        slot.filter_count = 0;
        for f in slot.filters.iter_mut() {
            f.active = false;
        }
        iface.qdisc_count += 1;
        Ok(slot_idx)
    }

    /// Remove a qdisc from an interface by slot index.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `ifindex` is out of range.
    /// - [`Error::NotFound`] if the qdisc slot is not active.
    pub fn del_qdisc(&mut self, ifindex: usize, qdisc_idx: usize) -> Result<()> {
        let iface = self
            .interfaces
            .get_mut(ifindex)
            .ok_or(Error::InvalidArgument)?;
        let slot = iface
            .qdiscs
            .get_mut(qdisc_idx)
            .ok_or(Error::InvalidArgument)?;
        if !slot.qdisc.active {
            return Err(Error::NotFound);
        }
        slot.qdisc.active = false;
        slot.filter_count = 0;
        for f in slot.filters.iter_mut() {
            f.active = false;
        }
        iface.qdisc_count = iface.qdisc_count.saturating_sub(1);
        Ok(())
    }

    /// Add a filter to a qdisc.
    ///
    /// Returns the filter slot index within the qdisc.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `ifindex` or `qdisc_idx`
    ///   is out of range, or the qdisc is not active.
    /// - [`Error::OutOfMemory`] if the qdisc already has
    ///   [`MAX_FILTERS_PER_QDISC`] filters.
    pub fn add_filter(
        &mut self,
        ifindex: usize,
        qdisc_idx: usize,
        filter: TcFilter,
    ) -> Result<usize> {
        let iface = self
            .interfaces
            .get_mut(ifindex)
            .ok_or(Error::InvalidArgument)?;
        let slot = iface
            .qdiscs
            .get_mut(qdisc_idx)
            .ok_or(Error::InvalidArgument)?;
        if !slot.qdisc.active {
            return Err(Error::InvalidArgument);
        }
        if slot.filter_count >= MAX_FILTERS_PER_QDISC {
            return Err(Error::OutOfMemory);
        }
        let filter_idx = slot
            .filters
            .iter()
            .position(|f| !f.active)
            .ok_or(Error::OutOfMemory)?;
        slot.filters[filter_idx] = filter;
        slot.filters[filter_idx].active = true;
        slot.filter_count += 1;
        Ok(filter_idx)
    }

    /// Remove a filter from a qdisc.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if any index is out of range.
    /// - [`Error::NotFound`] if the filter slot is not active.
    pub fn del_filter(
        &mut self,
        ifindex: usize,
        qdisc_idx: usize,
        filter_idx: usize,
    ) -> Result<()> {
        let iface = self
            .interfaces
            .get_mut(ifindex)
            .ok_or(Error::InvalidArgument)?;
        let slot = iface
            .qdiscs
            .get_mut(qdisc_idx)
            .ok_or(Error::InvalidArgument)?;
        let filter = slot
            .filters
            .get_mut(filter_idx)
            .ok_or(Error::InvalidArgument)?;
        if !filter.active {
            return Err(Error::NotFound);
        }
        filter.active = false;
        slot.filter_count = slot.filter_count.saturating_sub(1);
        Ok(())
    }

    /// Classify a packet against the filters of a qdisc.
    ///
    /// Filters are evaluated in priority order (lowest value first).
    /// Returns the action of the first matching filter, or
    /// [`TcAction::Ok`] if no filter matches.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if any index is out of
    /// range or the qdisc is not active.
    pub fn classify(
        &self,
        ifindex: usize,
        qdisc_idx: usize,
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
    ) -> Result<TcAction> {
        let iface = self.interfaces.get(ifindex).ok_or(Error::InvalidArgument)?;
        let slot = iface.qdiscs.get(qdisc_idx).ok_or(Error::InvalidArgument)?;
        if !slot.qdisc.active {
            return Err(Error::InvalidArgument);
        }
        // Find the matching filter with the lowest (highest-priority)
        // priority value.
        let mut best_action = TcAction::Ok;
        let mut best_prio = u16::MAX;
        for filter in &slot.filters {
            if filter.active
                && filter.priority < best_prio
                && filter.matches(src_ip, dst_ip, src_port, dst_port)
            {
                best_prio = filter.priority;
                best_action = filter.action;
            }
        }
        Ok(best_action)
    }

    /// Enqueue a packet into a qdisc.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if any index is out of range,
    ///   the qdisc is not active, or the packet is invalid.
    /// - [`Error::OutOfMemory`] if the qdisc queue is full.
    pub fn enqueue(
        &mut self,
        ifindex: usize,
        qdisc_idx: usize,
        data: &[u8],
        tos: u8,
    ) -> Result<()> {
        let iface = self
            .interfaces
            .get_mut(ifindex)
            .ok_or(Error::InvalidArgument)?;
        let slot = iface
            .qdiscs
            .get_mut(qdisc_idx)
            .ok_or(Error::InvalidArgument)?;
        if !slot.qdisc.active {
            return Err(Error::InvalidArgument);
        }
        slot.qdisc.enqueue(data, tos)
    }

    /// Dequeue the next packet from a qdisc.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if any index is out of range
    ///   or the qdisc is not active.
    /// - [`Error::WouldBlock`] if the queue is empty.
    pub fn dequeue(
        &mut self,
        ifindex: usize,
        qdisc_idx: usize,
        out: &mut [u8; QDISC_PACKET_SIZE],
    ) -> Result<usize> {
        let iface = self
            .interfaces
            .get_mut(ifindex)
            .ok_or(Error::InvalidArgument)?;
        let slot = iface
            .qdiscs
            .get_mut(qdisc_idx)
            .ok_or(Error::InvalidArgument)?;
        if !slot.qdisc.active {
            return Err(Error::InvalidArgument);
        }
        slot.qdisc.dequeue(out)
    }

    /// Tick all TBF qdiscs across all interfaces (token
    /// replenishment).
    pub fn tick_all(&mut self) {
        for iface in &mut self.interfaces {
            for slot in &mut iface.qdiscs {
                if slot.qdisc.active {
                    slot.qdisc.tick();
                }
            }
        }
    }
}
