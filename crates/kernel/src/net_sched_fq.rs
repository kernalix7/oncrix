// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Fair Queueing (FQ) packet scheduler.
//!
//! Implements a per-flow fair queueing discipline that ensures
//! equitable bandwidth distribution among competing flows:
//!
//! - **Flow identification** ([`FlowKey`]): 5-tuple hashing for
//!   flow classification (src/dst addr, src/dst port, protocol).
//! - **Per-flow queues** ([`FqFlowQueue`]): individual FIFO queues
//!   with virtual time tracking for DRR scheduling.
//! - **Packet descriptors** ([`FqPacket`]): metadata for enqueued
//!   packets including size, timestamp, and flow association.
//! - **Pacing engine** ([`PacingEngine`]): TSO/GSO-aware packet
//!   pacing with per-flow rate limiting.
//! - **Scheduler** ([`FqScheduler`]): main scheduling engine with
//!   deficit round-robin (DRR) across active flows.
//! - **Statistics** ([`FqStats`]): comprehensive counters for
//!   monitoring scheduler behavior.
//!
//! The FQ scheduler groups packets by flow (using a hash of the
//! 5-tuple), maintains a virtual time clock for fairness, and
//! serves flows in round-robin order with deficit tracking.
//!
//! Reference: Linux `net/sched/sch_fq.c`, `net/sched/sch_fq_codel.c`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum number of flow queues.
const MAX_FLOWS: usize = 256;

/// Maximum packets per flow queue.
const MAX_PACKETS_PER_FLOW: usize = 128;

/// Maximum total packets across all flows.
const MAX_TOTAL_PACKETS: usize = 4096;

/// Default quantum (bytes served per round).
const DEFAULT_QUANTUM: u32 = 3028; // ~2 MSS
/// Minimum quantum.
const MIN_QUANTUM: u32 = 256;

/// Maximum quantum.
const MAX_QUANTUM: u32 = 65536;

/// Default initial pacing rate (bytes per second).
const DEFAULT_PACING_RATE_BPS: u64 = 0; // 0 = no pacing

/// Default flow limit (max packets per flow).
const DEFAULT_FLOW_LIMIT: u32 = 100;

/// Orphan mask for flow hash (number of orphan queues).
const ORPHAN_MASK: usize = 15;

/// Number of priority bands (high, medium, low).
const NUM_BANDS: usize = 3;

/// Band index for high-priority traffic.
const BAND_HIGH: usize = 0;

/// Band index for normal traffic.
const BAND_NORMAL: usize = 1;

/// Band index for bulk traffic.
const BAND_BULK: usize = 2;

/// Maximum number of active flows in the run-list.
const MAX_ACTIVE_FLOWS: usize = 128;

/// Horizon for detecting stale flows (microseconds, 2s).
const FLOW_STALE_HORIZON_US: u64 = 2_000_000;

/// Hash table size for flow lookup.
const FLOW_HASH_SIZE: usize = 256;

// ── FlowKey ────────────────────────────────────────────────────────

/// 5-tuple flow identifier for packet classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowKey {
    /// Source address hash (32-bit).
    pub src_addr: u32,
    /// Destination address hash (32-bit).
    pub dst_addr: u32,
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// IP protocol number.
    pub protocol: u8,
}

impl FlowKey {
    /// Create a new flow key.
    pub const fn new(
        src_addr: u32,
        dst_addr: u32,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Self {
        Self {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            protocol,
        }
    }

    /// Compute a hash for flow table lookup.
    ///
    /// Uses a simple multiplicative hash (FNV-1a inspired).
    pub fn hash(&self) -> u32 {
        let mut h: u32 = 0x811c_9dc5;
        h = h.wrapping_mul(0x0100_0193) ^ self.src_addr;
        h = h.wrapping_mul(0x0100_0193) ^ self.dst_addr;
        h = h.wrapping_mul(0x0100_0193) ^ (self.src_port as u32);
        h = h.wrapping_mul(0x0100_0193) ^ (self.dst_port as u32);
        h = h.wrapping_mul(0x0100_0193) ^ (self.protocol as u32);
        h
    }

    /// Return the flow hash bucket index.
    pub fn bucket(&self) -> usize {
        (self.hash() as usize) % FLOW_HASH_SIZE
    }
}

impl Default for FlowKey {
    fn default() -> Self {
        Self::new(0, 0, 0, 0, 0)
    }
}

// ── FqPacket ───────────────────────────────────────────────────────

/// Descriptor for a packet in the FQ scheduler.
#[derive(Debug, Clone, Copy)]
pub struct FqPacket {
    /// Packet length in bytes.
    pub length: u32,
    /// Enqueue timestamp (microseconds since boot).
    pub enqueue_us: u64,
    /// Dequeue timestamp (0 if still queued).
    pub dequeue_us: u64,
    /// Flow key hash for this packet.
    pub flow_hash: u32,
    /// Priority band (0=high, 1=normal, 2=bulk).
    pub band: u8,
    /// IP protocol TOS/DSCP value.
    pub tos: u8,
    /// Sequence number within the flow.
    pub seq: u32,
    /// Whether this packet slot is in use.
    pub active: bool,
}

impl FqPacket {
    /// Create an empty packet descriptor.
    pub const fn new() -> Self {
        Self {
            length: 0,
            enqueue_us: 0,
            dequeue_us: 0,
            flow_hash: 0,
            band: BAND_NORMAL as u8,
            tos: 0,
            seq: 0,
            active: false,
        }
    }

    /// Compute the sojourn time (time in queue).
    pub fn sojourn_us(&self, now_us: u64) -> u64 {
        if self.dequeue_us > 0 {
            self.dequeue_us.saturating_sub(self.enqueue_us)
        } else {
            now_us.saturating_sub(self.enqueue_us)
        }
    }
}

impl Default for FqPacket {
    fn default() -> Self {
        Self::new()
    }
}

// ── FqFlowQueue ────────────────────────────────────────────────────

/// Per-flow FIFO queue with virtual time tracking.
#[derive(Debug)]
pub struct FqFlowQueue {
    /// Flow key for this queue.
    pub key: FlowKey,
    /// Flow hash (cached from key).
    pub flow_hash: u32,
    /// Packet ring buffer indices (into global packet pool).
    packet_indices: [u16; MAX_PACKETS_PER_FLOW],
    /// Read pointer.
    head: usize,
    /// Write pointer.
    tail: usize,
    /// Number of enqueued packets.
    pub count: u32,
    /// Total bytes enqueued.
    pub total_bytes: u64,
    /// Virtual finish time for DRR scheduling.
    pub virtual_time: u64,
    /// Deficit counter (bytes credit).
    pub deficit: i32,
    /// Per-flow pacing rate (bytes per second, 0 = no pacing).
    pub pacing_rate_bps: u64,
    /// Next allowed send time for pacing (microseconds).
    pub next_send_us: u64,
    /// Priority band assignment.
    pub band: u8,
    /// Whether this flow is in the active run-list.
    pub is_active: bool,
    /// Whether this flow slot is in use.
    pub allocated: bool,
    /// Timestamp of last activity.
    pub last_activity_us: u64,
    /// Total packets served from this flow.
    pub total_served: u64,
    /// Total bytes served from this flow.
    pub total_bytes_served: u64,
}

impl FqFlowQueue {
    /// Create an empty flow queue.
    pub const fn new() -> Self {
        Self {
            key: FlowKey::new(0, 0, 0, 0, 0),
            flow_hash: 0,
            packet_indices: [0u16; MAX_PACKETS_PER_FLOW],
            head: 0,
            tail: 0,
            count: 0,
            total_bytes: 0,
            virtual_time: 0,
            deficit: 0,
            pacing_rate_bps: DEFAULT_PACING_RATE_BPS,
            next_send_us: 0,
            band: BAND_NORMAL as u8,
            is_active: false,
            allocated: false,
            last_activity_us: 0,
            total_served: 0,
            total_bytes_served: 0,
        }
    }

    /// Initialize this flow queue.
    pub fn init(&mut self, key: FlowKey, band: u8) {
        self.key = key;
        self.flow_hash = key.hash();
        self.head = 0;
        self.tail = 0;
        self.count = 0;
        self.total_bytes = 0;
        self.virtual_time = 0;
        self.deficit = 0;
        self.pacing_rate_bps = DEFAULT_PACING_RATE_BPS;
        self.next_send_us = 0;
        self.band = band;
        self.is_active = false;
        self.allocated = true;
        self.last_activity_us = 0;
        self.total_served = 0;
        self.total_bytes_served = 0;
    }

    /// Enqueue a packet index.
    pub fn enqueue(&mut self, pkt_idx: u16) -> Result<()> {
        if self.count as usize >= MAX_PACKETS_PER_FLOW {
            return Err(Error::OutOfMemory);
        }
        self.packet_indices[self.tail] = pkt_idx;
        self.tail = (self.tail + 1) % MAX_PACKETS_PER_FLOW;
        self.count += 1;
        Ok(())
    }

    /// Dequeue the next packet index.
    pub fn dequeue(&mut self) -> Option<u16> {
        if self.count == 0 {
            return None;
        }
        let idx = self.packet_indices[self.head];
        self.head = (self.head + 1) % MAX_PACKETS_PER_FLOW;
        self.count -= 1;
        self.total_served += 1;
        Some(idx)
    }

    /// Peek at the next packet index without dequeuing.
    pub fn peek(&self) -> Option<u16> {
        if self.count == 0 {
            return None;
        }
        Some(self.packet_indices[self.head])
    }

    /// Whether this flow queue is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Whether this flow is stale (no recent activity).
    pub fn is_stale(&self, now_us: u64) -> bool {
        self.allocated
            && self.count == 0
            && now_us.saturating_sub(self.last_activity_us) > FLOW_STALE_HORIZON_US
    }

    /// Reset this flow queue for reuse.
    pub fn reset(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.count = 0;
        self.total_bytes = 0;
        self.virtual_time = 0;
        self.deficit = 0;
        self.is_active = false;
        self.allocated = false;
    }
}

impl Default for FqFlowQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ── PacingEngine ───────────────────────────────────────────────────

/// Packet pacing engine for rate-controlled transmission.
///
/// Computes per-packet delays based on the flow's configured
/// pacing rate to smooth traffic bursts.
pub struct PacingEngine {
    /// Global maximum pacing rate (bytes per second).
    pub max_rate_bps: u64,
    /// Whether pacing is enabled globally.
    pub enabled: bool,
    /// Total packets paced (delayed).
    pub paced_count: u64,
    /// Total delay applied (microseconds).
    pub total_delay_us: u64,
}

impl PacingEngine {
    /// Create a new pacing engine.
    pub const fn new() -> Self {
        Self {
            max_rate_bps: 0,
            enabled: false,
            paced_count: 0,
            total_delay_us: 0,
        }
    }

    /// Compute the transmit delay for a packet.
    ///
    /// Returns the number of microseconds to delay before
    /// sending, based on the flow's pacing rate.
    pub fn compute_delay(&self, pkt_len: u32, flow_rate_bps: u64) -> u64 {
        if !self.enabled || flow_rate_bps == 0 {
            return 0;
        }
        let rate = if self.max_rate_bps > 0 {
            flow_rate_bps.min(self.max_rate_bps)
        } else {
            flow_rate_bps
        };
        if rate == 0 {
            return 0;
        }
        // delay = packet_size / rate (in microseconds)
        (pkt_len as u64 * 1_000_000) / rate
    }

    /// Check if a flow should be paced (delayed).
    ///
    /// Returns the delay in microseconds, or 0 if no pacing.
    pub fn pace_flow(
        &mut self,
        pkt_len: u32,
        flow_rate_bps: u64,
        flow_next_send_us: u64,
        now_us: u64,
    ) -> u64 {
        if !self.enabled || flow_rate_bps == 0 {
            return 0;
        }
        if now_us >= flow_next_send_us {
            let delay = self.compute_delay(pkt_len, flow_rate_bps);
            if delay > 0 {
                self.paced_count += 1;
                self.total_delay_us = self.total_delay_us.saturating_add(delay);
            }
            delay
        } else {
            let wait = flow_next_send_us.saturating_sub(now_us);
            self.paced_count += 1;
            self.total_delay_us = self.total_delay_us.saturating_add(wait);
            wait
        }
    }
}

impl Default for PacingEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── ActiveFlowList ─────────────────────────────────────────────────

/// List of active (non-empty) flow indices for DRR scheduling.
#[derive(Debug)]
pub struct ActiveFlowList {
    /// Flow indices in round-robin order.
    entries: [u16; MAX_ACTIVE_FLOWS],
    /// Number of entries.
    count: usize,
    /// Current cursor for round-robin.
    cursor: usize,
}

impl ActiveFlowList {
    /// Create an empty active flow list.
    pub const fn new() -> Self {
        Self {
            entries: [0u16; MAX_ACTIVE_FLOWS],
            count: 0,
            cursor: 0,
        }
    }

    /// Add a flow to the active list.
    pub fn add(&mut self, flow_idx: u16) -> Result<()> {
        if self.count >= MAX_ACTIVE_FLOWS {
            return Err(Error::OutOfMemory);
        }
        // Avoid duplicates
        if self.entries[..self.count].contains(&flow_idx) {
            return Ok(());
        }
        self.entries[self.count] = flow_idx;
        self.count += 1;
        Ok(())
    }

    /// Remove a flow from the active list.
    pub fn remove(&mut self, flow_idx: u16) {
        if let Some(pos) = self.entries[..self.count]
            .iter()
            .position(|&e| e == flow_idx)
        {
            self.entries[pos] = self.entries[self.count - 1];
            self.count -= 1;
            if self.cursor >= self.count && self.count > 0 {
                self.cursor = 0;
            }
        }
    }

    /// Get the next flow index in round-robin order.
    pub fn next(&mut self) -> Option<u16> {
        if self.count == 0 {
            return None;
        }
        let idx = self.entries[self.cursor];
        self.cursor = (self.cursor + 1) % self.count;
        Some(idx)
    }

    /// Return the number of active flows.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for ActiveFlowList {
    fn default() -> Self {
        Self::new()
    }
}

// ── FqStats ────────────────────────────────────────────────────────

/// Comprehensive statistics for the FQ scheduler.
#[derive(Debug, Clone, Copy)]
pub struct FqStats {
    /// Total packets enqueued.
    pub enqueued: u64,
    /// Total packets dequeued.
    pub dequeued: u64,
    /// Total packets dropped (queue full).
    pub dropped: u64,
    /// Total bytes enqueued.
    pub bytes_enqueued: u64,
    /// Total bytes dequeued.
    pub bytes_dequeued: u64,
    /// Number of flow hash collisions.
    pub hash_collisions: u64,
    /// Number of new flows created.
    pub flows_created: u64,
    /// Number of flows recycled (stale).
    pub flows_recycled: u64,
    /// Current number of active flows.
    pub active_flows: u32,
    /// Current total packet count.
    pub total_packets: u32,
    /// Peak active flow count.
    pub peak_flows: u32,
    /// Peak total packet count.
    pub peak_packets: u32,
    /// Total rounds of DRR scheduling.
    pub drr_rounds: u64,
    /// Packets dequeued per band.
    pub band_dequeued: [u64; NUM_BANDS],
}

impl FqStats {
    /// Create empty statistics.
    pub const fn new() -> Self {
        Self {
            enqueued: 0,
            dequeued: 0,
            dropped: 0,
            bytes_enqueued: 0,
            bytes_dequeued: 0,
            hash_collisions: 0,
            flows_created: 0,
            flows_recycled: 0,
            active_flows: 0,
            total_packets: 0,
            peak_flows: 0,
            peak_packets: 0,
            drr_rounds: 0,
            band_dequeued: [0u64; NUM_BANDS],
        }
    }
}

impl Default for FqStats {
    fn default() -> Self {
        Self::new()
    }
}

// ── FqConfig ───────────────────────────────────────────────────────

/// Configuration for the FQ scheduler.
#[derive(Debug, Clone, Copy)]
pub struct FqConfig {
    /// Quantum (bytes served per DRR round).
    pub quantum: u32,
    /// Per-flow packet limit.
    pub flow_limit: u32,
    /// Global packet limit.
    pub global_limit: u32,
    /// Initial pacing rate (bytes per second, 0 = no pacing).
    pub initial_pacing_rate_bps: u64,
    /// Maximum pacing rate (0 = no limit).
    pub max_pacing_rate_bps: u64,
    /// Whether flow-level pacing is enabled.
    pub pacing_enabled: bool,
    /// Orphan flow mask (for socket-less packets).
    pub orphan_mask: usize,
}

impl FqConfig {
    /// Create default configuration.
    pub const fn new() -> Self {
        Self {
            quantum: DEFAULT_QUANTUM,
            flow_limit: DEFAULT_FLOW_LIMIT,
            global_limit: MAX_TOTAL_PACKETS as u32,
            initial_pacing_rate_bps: DEFAULT_PACING_RATE_BPS,
            max_pacing_rate_bps: 0,
            pacing_enabled: false,
            orphan_mask: ORPHAN_MASK,
        }
    }

    /// Validate configuration.
    pub fn validate(&self) -> Result<()> {
        if self.quantum < MIN_QUANTUM || self.quantum > MAX_QUANTUM {
            return Err(Error::InvalidArgument);
        }
        if self.flow_limit == 0 || self.global_limit == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for FqConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ── FqScheduler ────────────────────────────────────────────────────

/// Fair Queueing packet scheduler.
///
/// Classifies packets into per-flow queues and serves them using
/// deficit round-robin (DRR) scheduling for fair bandwidth sharing.
pub struct FqScheduler {
    /// Scheduler configuration.
    pub config: FqConfig,
    /// Per-flow queues.
    flows: [FqFlowQueue; MAX_FLOWS],
    /// Flow hash table (flow index per hash bucket).
    flow_hash_table: [u16; FLOW_HASH_SIZE],
    /// Active flow run-lists per band.
    active_lists: [ActiveFlowList; NUM_BANDS],
    /// Packet pool.
    packets: [FqPacket; MAX_TOTAL_PACKETS],
    /// Free packet index stack.
    free_packets: [u16; MAX_TOTAL_PACKETS],
    /// Number of free packet slots.
    free_count: usize,
    /// Pacing engine.
    pub pacer: PacingEngine,
    /// Scheduler statistics.
    pub stats: FqStats,
    /// Virtual time clock.
    virtual_time: u64,
    /// Current DRR band being served.
    current_band: usize,
    /// Whether the scheduler is initialized.
    initialized: bool,
}

impl FqScheduler {
    /// Create a new uninitialized scheduler.
    pub const fn new() -> Self {
        Self {
            config: FqConfig::new(),
            flows: [const { FqFlowQueue::new() }; MAX_FLOWS],
            flow_hash_table: [u16::MAX; FLOW_HASH_SIZE],
            active_lists: [const { ActiveFlowList::new() }; NUM_BANDS],
            packets: [const { FqPacket::new() }; MAX_TOTAL_PACKETS],
            free_packets: [0u16; MAX_TOTAL_PACKETS],
            free_count: 0,
            pacer: PacingEngine::new(),
            stats: FqStats::new(),
            virtual_time: 0,
            current_band: BAND_HIGH,
            initialized: false,
        }
    }

    /// Initialize the scheduler.
    pub fn init(&mut self, config: FqConfig) -> Result<()> {
        config.validate()?;
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        self.config = config;
        self.pacer.enabled = config.pacing_enabled;
        self.pacer.max_rate_bps = config.max_pacing_rate_bps;

        // Initialize free packet list
        for i in 0..MAX_TOTAL_PACKETS {
            self.free_packets[i] = i as u16;
        }
        self.free_count = MAX_TOTAL_PACKETS;

        // Clear hash table
        self.flow_hash_table = [u16::MAX; FLOW_HASH_SIZE];
        self.initialized = true;
        Ok(())
    }

    /// Enqueue a packet.
    pub fn enqueue(&mut self, key: FlowKey, length: u32, tos: u8, now_us: u64) -> Result<()> {
        if !self.initialized {
            return Err(Error::NotImplemented);
        }
        if self.stats.total_packets >= self.config.global_limit {
            self.stats.dropped += 1;
            return Err(Error::OutOfMemory);
        }

        // Allocate packet slot
        let pkt_idx = self.alloc_packet()?;
        let band = tos_to_band(tos);

        // Set up packet
        self.packets[pkt_idx as usize] = FqPacket {
            length,
            enqueue_us: now_us,
            dequeue_us: 0,
            flow_hash: key.hash(),
            band,
            tos,
            seq: 0,
            active: true,
        };

        // Find or create flow
        let flow_idx = self.find_or_create_flow(key, band)?;
        let flow = &mut self.flows[flow_idx];

        if flow.count >= self.config.flow_limit {
            self.free_packet(pkt_idx);
            self.stats.dropped += 1;
            return Err(Error::OutOfMemory);
        }

        flow.enqueue(pkt_idx)?;
        flow.total_bytes += length as u64;
        flow.last_activity_us = now_us;

        // Add to active list if not already there
        if !flow.is_active {
            flow.is_active = true;
            flow.deficit = self.config.quantum as i32;
            let band_idx = flow.band as usize;
            if band_idx < NUM_BANDS {
                let _ = self.active_lists[band_idx].add(flow_idx as u16);
            }
        }

        self.stats.enqueued += 1;
        self.stats.bytes_enqueued += length as u64;
        self.stats.total_packets += 1;
        if self.stats.total_packets > self.stats.peak_packets {
            self.stats.peak_packets = self.stats.total_packets;
        }

        Ok(())
    }

    /// Dequeue the next packet.
    ///
    /// Returns the packet descriptor and flow index.
    pub fn dequeue(&mut self, now_us: u64) -> Option<(FqPacket, usize)> {
        if !self.initialized || self.stats.total_packets == 0 {
            return None;
        }

        // Try each band in priority order
        for band_offset in 0..NUM_BANDS {
            let band = (self.current_band + band_offset) % NUM_BANDS;
            if let Some(result) = self.dequeue_from_band(band, now_us) {
                return Some(result);
            }
        }

        None
    }

    /// Dequeue a packet from a specific band.
    fn dequeue_from_band(&mut self, band: usize, now_us: u64) -> Option<(FqPacket, usize)> {
        let max_rounds = self.active_lists[band].count();
        for _ in 0..max_rounds {
            let flow_idx = self.active_lists[band].next()? as usize;

            if flow_idx >= MAX_FLOWS || !self.flows[flow_idx].allocated {
                continue;
            }

            // Check pacing
            if self.flows[flow_idx].pacing_rate_bps > 0
                && now_us < self.flows[flow_idx].next_send_us
            {
                continue;
            }

            if self.flows[flow_idx].deficit <= 0 {
                self.flows[flow_idx].deficit += self.config.quantum as i32;
                self.stats.drr_rounds += 1;
                continue;
            }

            if let Some(pkt_idx) = self.flows[flow_idx].dequeue() {
                let pkt_idx = pkt_idx as usize;
                if pkt_idx >= MAX_TOTAL_PACKETS {
                    continue;
                }
                let pkt_len = self.packets[pkt_idx].length;
                let pkt_dequeue = self.packets[pkt_idx];
                self.packets[pkt_idx].active = false;

                self.flows[flow_idx].deficit -= pkt_len as i32;
                self.flows[flow_idx].total_bytes_served += pkt_len as u64;
                self.flows[flow_idx].last_activity_us = now_us;

                // Update pacing
                if self.flows[flow_idx].pacing_rate_bps > 0 {
                    let delay = self
                        .pacer
                        .compute_delay(pkt_len, self.flows[flow_idx].pacing_rate_bps);
                    self.flows[flow_idx].next_send_us = now_us.saturating_add(delay);
                }

                // Free packet slot
                self.free_packet(pkt_idx as u16);

                // Deactivate empty flow
                if self.flows[flow_idx].is_empty() {
                    self.flows[flow_idx].is_active = false;
                    self.active_lists[band].remove(flow_idx as u16);
                }

                self.stats.dequeued += 1;
                self.stats.bytes_dequeued += pkt_len as u64;
                self.stats.total_packets = self.stats.total_packets.saturating_sub(1);
                if band < NUM_BANDS {
                    self.stats.band_dequeued[band] += 1;
                }

                // Advance virtual time
                self.virtual_time = self.virtual_time.wrapping_add(pkt_len as u64);

                return Some((pkt_dequeue, flow_idx));
            }

            // Flow is empty, remove from active list
            self.flows[flow_idx].is_active = false;
            self.active_lists[band].remove(flow_idx as u16);
        }

        None
    }

    /// Reclaim stale flow entries.
    pub fn gc(&mut self, now_us: u64) -> usize {
        let mut reclaimed = 0;
        for i in 0..MAX_FLOWS {
            if self.flows[i].is_stale(now_us) {
                let hash = self.flows[i].flow_hash;
                let bucket = (hash as usize) % FLOW_HASH_SIZE;
                if self.flow_hash_table[bucket] == i as u16 {
                    self.flow_hash_table[bucket] = u16::MAX;
                }
                self.flows[i].reset();
                self.stats.flows_recycled += 1;
                reclaimed += 1;
            }
        }
        self.update_active_flow_count();
        reclaimed
    }

    /// Return the number of active flows.
    pub fn active_flow_count(&self) -> usize {
        self.flows.iter().filter(|f| f.allocated).count()
    }

    /// Return the total number of queued packets.
    pub fn total_packets(&self) -> u32 {
        self.stats.total_packets
    }

    /// Update the active flow count statistic.
    fn update_active_flow_count(&mut self) {
        let count = self.active_flow_count() as u32;
        self.stats.active_flows = count;
        if count > self.stats.peak_flows {
            self.stats.peak_flows = count;
        }
    }

    /// Find or create a flow queue for a key.
    fn find_or_create_flow(&mut self, key: FlowKey, band: u8) -> Result<usize> {
        let bucket = key.bucket();
        let existing = self.flow_hash_table[bucket];

        if existing != u16::MAX {
            let idx = existing as usize;
            if idx < MAX_FLOWS
                && self.flows[idx].allocated
                && self.flows[idx].flow_hash == key.hash()
            {
                return Ok(idx);
            }
            self.stats.hash_collisions += 1;
        }

        // Find a free flow slot
        let slot = self
            .flows
            .iter()
            .position(|f| !f.allocated)
            .ok_or(Error::OutOfMemory)?;

        self.flows[slot].init(key, band);
        self.flows[slot].pacing_rate_bps = self.config.initial_pacing_rate_bps;
        self.flow_hash_table[bucket] = slot as u16;
        self.stats.flows_created += 1;
        self.update_active_flow_count();

        Ok(slot)
    }

    /// Allocate a packet slot from the free list.
    fn alloc_packet(&mut self) -> Result<u16> {
        if self.free_count == 0 {
            return Err(Error::OutOfMemory);
        }
        self.free_count -= 1;
        Ok(self.free_packets[self.free_count])
    }

    /// Free a packet slot back to the free list.
    fn free_packet(&mut self, idx: u16) {
        if self.free_count < MAX_TOTAL_PACKETS {
            self.free_packets[self.free_count] = idx;
            self.free_count += 1;
        }
    }
}

impl Default for FqScheduler {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper functions ───────────────────────────────────────────────

/// Map TOS/DSCP value to a priority band.
fn tos_to_band(tos: u8) -> u8 {
    let dscp = tos >> 2;
    match dscp {
        // EF (Expedited Forwarding)
        46 => BAND_HIGH as u8,
        // CS6, CS7 (Control traffic)
        48..=56 => BAND_HIGH as u8,
        // AF4x (high priority)
        32..=38 => BAND_HIGH as u8,
        // CS1 (bulk/scavenger)
        8 => BAND_BULK as u8,
        // Default / best effort
        _ => BAND_NORMAL as u8,
    }
}
