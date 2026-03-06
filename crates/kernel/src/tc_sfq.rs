// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Stochastic Fairness Queueing (SFQ) discipline for the ONCRIX
//! traffic control subsystem.
//!
//! SFQ uses a hash function to classify packets into per-flow queues
//! and serves them with Deficit Round-Robin (DRR) to ensure fair
//! bandwidth sharing among competing flows.  Periodic hash
//! perturbation (re-seeding) prevents persistent collisions.
//!
//! # Architecture
//!
//! ```text
//! packet → SfqHash(5-tuple) → flow index → SfqFlow queue
//!                                              ↓
//!                              SfqQdisc round-robin dequeue (DRR)
//! ```
//!
//! Key components:
//!
//! - [`SfqHash`]: FNV-1a based flow hash mapping a 5-tuple to a
//!   flow index.
//! - [`SfqFlow`]: per-flow packet queue with DRR allotment tracking.
//! - [`SfqQdisc`]: the SFQ queuing discipline managing
//!   [`MAX_SFQ_FLOWS`] flow buckets with round-robin dequeue and
//!   periodic hash perturbation.
//! - [`SfqStats`]: traffic counters for monitoring.
//!
//! Reference: Linux `net/sched/sch_sfq.c`.

use oncrix_lib::{Error, Result};

// =========================================================================
// Constants
// =========================================================================

/// Maximum number of flow buckets in the SFQ.
const MAX_SFQ_FLOWS: usize = 128;

/// Maximum number of packets per flow queue.
const SFQ_FLOW_QUEUE_LEN: usize = 32;

/// Maximum packet size in the SFQ queue (bytes).
const SFQ_PACKET_SIZE: usize = 2048;

/// Default quantum for DRR (bytes per round).
/// Corresponds to the maximum Ethernet frame size.
const SFQ_DEFAULT_QUANTUM: u32 = 1514;

/// Default perturbation period in ticks (0 = disabled).
const SFQ_DEFAULT_PERTURB_PERIOD: u32 = 10;

/// Maximum number of active flows tracked in the round-robin list.
const MAX_ACTIVE_FLOWS: usize = MAX_SFQ_FLOWS;

/// FNV-1a 32-bit offset basis.
const FNV_OFFSET_BASIS: u32 = 0x811C_9DC5;

/// FNV-1a 32-bit prime.
const FNV_PRIME: u32 = 0x0100_0193;

// =========================================================================
// SfqPacket
// =========================================================================

/// A single packet stored in an SFQ flow queue.
#[derive(Clone)]
struct SfqPacket {
    /// Packet data buffer.
    data: [u8; SFQ_PACKET_SIZE],
    /// Actual length of valid data in `data`.
    len: usize,
    /// Whether this packet slot is occupied.
    occupied: bool,
}

impl Default for SfqPacket {
    fn default() -> Self {
        Self {
            data: [0u8; SFQ_PACKET_SIZE],
            len: 0,
            occupied: false,
        }
    }
}

// =========================================================================
// SfqHash
// =========================================================================

/// FNV-1a flow hash for SFQ packet classification.
///
/// Hashes the 5-tuple (source IP, destination IP, source port,
/// destination port, protocol) into a flow index in `0..num_flows`.
/// A perturbation seed is XORed into the hash to allow periodic
/// re-randomisation.
pub struct SfqHash {
    /// Perturbation seed XORed into the hash.
    pub seed: u32,
}

impl Default for SfqHash {
    fn default() -> Self {
        Self::new(0)
    }
}

impl SfqHash {
    /// Create a new SFQ hash with the given perturbation seed.
    pub const fn new(seed: u32) -> Self {
        Self { seed }
    }

    /// Compute the flow index for a 5-tuple.
    ///
    /// Uses FNV-1a with the perturbation seed to produce a hash,
    /// then maps it into `0..num_flows` via modulus.
    ///
    /// # Panics
    ///
    /// Panics in debug mode if `num_flows` is zero.
    pub fn hash(
        &self,
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        num_flows: usize,
    ) -> usize {
        let mut h: u32 = FNV_OFFSET_BASIS ^ self.seed;

        // Hash source IP (4 bytes).
        let src_bytes = src_ip.to_be_bytes();
        for &b in &src_bytes {
            h ^= b as u32;
            h = h.wrapping_mul(FNV_PRIME);
        }

        // Hash destination IP (4 bytes).
        let dst_bytes = dst_ip.to_be_bytes();
        for &b in &dst_bytes {
            h ^= b as u32;
            h = h.wrapping_mul(FNV_PRIME);
        }

        // Hash source port (2 bytes).
        let sp_bytes = src_port.to_be_bytes();
        for &b in &sp_bytes {
            h ^= b as u32;
            h = h.wrapping_mul(FNV_PRIME);
        }

        // Hash destination port (2 bytes).
        let dp_bytes = dst_port.to_be_bytes();
        for &b in &dp_bytes {
            h ^= b as u32;
            h = h.wrapping_mul(FNV_PRIME);
        }

        // Hash protocol (1 byte).
        h ^= protocol as u32;
        h = h.wrapping_mul(FNV_PRIME);

        (h as usize) % num_flows
    }
}

// =========================================================================
// SfqFlow
// =========================================================================

/// Per-flow packet queue with DRR allotment tracking.
///
/// Each flow bucket stores up to [`SFQ_FLOW_QUEUE_LEN`] packets and
/// tracks a deficit counter for Deficit Round-Robin scheduling.
pub struct SfqFlow {
    /// Flow hash value that this bucket currently holds.
    pub hash: u32,
    /// Ring buffer of packets.
    queue: [SfqPacket; SFQ_FLOW_QUEUE_LEN],
    /// Write index (head) into the ring buffer.
    head: usize,
    /// Read index (tail) into the ring buffer.
    tail: usize,
    /// Number of packets currently queued.
    count: usize,
    /// DRR deficit counter (remaining bytes this flow may send in
    /// the current round).
    pub allotment: i32,
    /// Whether this flow has any queued packets (is in the active
    /// list).
    active: bool,
}

impl Default for SfqFlow {
    fn default() -> Self {
        Self::new()
    }
}

impl SfqFlow {
    /// Create an empty flow.
    pub fn new() -> Self {
        Self {
            hash: 0,
            queue: core::array::from_fn(|_| SfqPacket::default()),
            head: 0,
            tail: 0,
            count: 0,
            allotment: 0,
            active: false,
        }
    }

    /// Enqueue a packet into this flow.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `data` is empty or exceeds
    ///   [`SFQ_PACKET_SIZE`].
    /// - [`Error::OutOfMemory`] if the flow queue is full.
    pub fn enqueue(&mut self, data: &[u8]) -> Result<()> {
        if data.is_empty() || data.len() > SFQ_PACKET_SIZE {
            return Err(Error::InvalidArgument);
        }
        if self.count >= SFQ_FLOW_QUEUE_LEN {
            return Err(Error::OutOfMemory);
        }
        self.queue[self.head].data[..data.len()].copy_from_slice(data);
        self.queue[self.head].len = data.len();
        self.queue[self.head].occupied = true;
        self.head = (self.head + 1) % SFQ_FLOW_QUEUE_LEN;
        self.count += 1;
        Ok(())
    }

    /// Dequeue the next packet from this flow.
    ///
    /// Copies packet data into `out` and returns the length.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WouldBlock`] if the flow queue is empty.
    pub fn dequeue(&mut self, out: &mut [u8; SFQ_PACKET_SIZE]) -> Result<usize> {
        if self.count == 0 {
            return Err(Error::WouldBlock);
        }
        let pkt = &self.queue[self.tail];
        let len = pkt.len;
        out[..len].copy_from_slice(&pkt.data[..len]);
        self.queue[self.tail].occupied = false;
        self.tail = (self.tail + 1) % SFQ_FLOW_QUEUE_LEN;
        self.count -= 1;
        Ok(len)
    }

    /// Peek at the length of the next packet without dequeuing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WouldBlock`] if the flow queue is empty.
    pub fn peek_len(&self) -> Result<usize> {
        if self.count == 0 {
            return Err(Error::WouldBlock);
        }
        Ok(self.queue[self.tail].len)
    }

    /// Return the number of packets in this flow queue.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return whether this flow queue is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// =========================================================================
// SfqStats
// =========================================================================

/// SFQ traffic counters for monitoring.
#[derive(Debug, Clone, Copy, Default)]
pub struct SfqStats {
    /// Total packets successfully enqueued.
    pub enqueued: u64,
    /// Total packets successfully dequeued.
    pub dequeued: u64,
    /// Total packets dropped (queue full).
    pub dropped: u64,
    /// Number of currently active flows.
    pub flows_active: u32,
    /// Number of hash perturbation events.
    pub perturbations: u64,
}

// =========================================================================
// SfqQdisc
// =========================================================================

/// Stochastic Fairness Queueing discipline.
///
/// Manages [`MAX_SFQ_FLOWS`] flow buckets served in Deficit
/// Round-Robin order.  Packets are classified into flows by hashing
/// the 5-tuple (src IP, dst IP, src port, dst port, protocol).
///
/// The hash function is periodically perturbed (re-seeded) to avoid
/// persistent collisions between flows.
pub struct SfqQdisc {
    /// Per-flow packet queues.
    flows: [SfqFlow; MAX_SFQ_FLOWS],
    /// Indices of active flows in round-robin order.
    active_flows: [usize; MAX_ACTIVE_FLOWS],
    /// Number of active flows.
    active_count: usize,
    /// Current position in the active flows list for DRR.
    current_idx: usize,
    /// DRR quantum — bytes added to each flow's deficit per round.
    pub quantum: u32,
    /// Flow hash function with perturbation seed.
    hasher: SfqHash,
    /// Perturbation period in ticks (0 = disabled).
    pub perturbation_period: u32,
    /// Current tick counter for perturbation timing.
    current_tick: u32,
    /// Traffic statistics.
    pub stats: SfqStats,
}

impl Default for SfqQdisc {
    fn default() -> Self {
        Self::new()
    }
}

impl SfqQdisc {
    /// Create a new SFQ qdisc with default parameters.
    pub fn new() -> Self {
        Self {
            flows: core::array::from_fn(|_| SfqFlow::new()),
            active_flows: [0usize; MAX_ACTIVE_FLOWS],
            active_count: 0,
            current_idx: 0,
            quantum: SFQ_DEFAULT_QUANTUM,
            hasher: SfqHash::new(0),
            perturbation_period: SFQ_DEFAULT_PERTURB_PERIOD,
            current_tick: 0,
            stats: SfqStats::default(),
        }
    }

    /// Create a new SFQ qdisc with custom quantum and perturbation
    /// period.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `quantum` is zero.
    pub fn with_params(quantum: u32, perturbation_period: u32) -> Result<Self> {
        if quantum == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            quantum,
            perturbation_period,
            ..Self::new()
        })
    }

    /// Enqueue a packet, classifying it into a flow by 5-tuple hash.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `data` is empty or exceeds
    ///   [`SFQ_PACKET_SIZE`].
    /// - [`Error::OutOfMemory`] if the target flow queue is full.
    pub fn enqueue(
        &mut self,
        data: &[u8],
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Result<()> {
        if data.is_empty() || data.len() > SFQ_PACKET_SIZE {
            return Err(Error::InvalidArgument);
        }

        let flow_idx =
            self.hasher
                .hash(src_ip, dst_ip, src_port, dst_port, protocol, MAX_SFQ_FLOWS);

        let result = self.flows[flow_idx].enqueue(data);
        match result {
            Ok(()) => {
                self.stats.enqueued = self.stats.enqueued.wrapping_add(1);

                // Add to active list if this flow was previously empty.
                if !self.flows[flow_idx].active {
                    self.flows[flow_idx].active = true;
                    self.flows[flow_idx].allotment = self.quantum as i32;
                    self.add_active_flow(flow_idx);
                }
                Ok(())
            }
            Err(e) => {
                self.stats.dropped = self.stats.dropped.wrapping_add(1);
                Err(e)
            }
        }
    }

    /// Dequeue the next packet using Deficit Round-Robin across
    /// active flows.
    ///
    /// Each active flow receives `quantum` bytes of deficit per
    /// round.  A flow may send a packet only if its deficit counter
    /// covers the packet size.  Flows that exhaust their queue are
    /// removed from the active list.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WouldBlock`] if no active flows have
    /// packets.
    pub fn dequeue(&mut self, out: &mut [u8; SFQ_PACKET_SIZE]) -> Result<usize> {
        if self.active_count == 0 {
            return Err(Error::WouldBlock);
        }

        // Try each active flow starting from current_idx.
        let start = self.current_idx;
        let mut attempts = 0;

        loop {
            if attempts >= self.active_count {
                // All flows checked, replenish deficits and retry
                // once.
                for i in 0..self.active_count {
                    let fidx = self.active_flows[i];
                    self.flows[fidx].allotment += self.quantum as i32;
                }

                // Second pass after replenishment.
                for _ in 0..self.active_count {
                    let idx = self.current_idx % self.active_count;
                    let flow_idx = self.active_flows[idx];
                    let flow = &mut self.flows[flow_idx];

                    if let Ok(pkt_len) = flow.peek_len() {
                        if flow.allotment >= pkt_len as i32 {
                            let len = flow.dequeue(out)?;
                            flow.allotment -= len as i32;
                            self.stats.dequeued = self.stats.dequeued.wrapping_add(1);

                            if flow.is_empty() {
                                flow.active = false;
                                self.remove_active_flow(idx);
                            } else {
                                self.current_idx = (idx + 1) % self.active_count.max(1);
                            }
                            return Ok(len);
                        }
                    }
                    self.current_idx = (self.current_idx + 1) % self.active_count.max(1);
                }
                return Err(Error::WouldBlock);
            }

            let idx = (start + attempts) % self.active_count;
            let flow_idx = self.active_flows[idx];
            let flow = &mut self.flows[flow_idx];

            if let Ok(pkt_len) = flow.peek_len() {
                if flow.allotment >= pkt_len as i32 {
                    let len = flow.dequeue(out)?;
                    flow.allotment -= len as i32;
                    self.stats.dequeued = self.stats.dequeued.wrapping_add(1);

                    if flow.is_empty() {
                        flow.active = false;
                        self.remove_active_flow(idx);
                        // After removal, current_idx should point to
                        // the same position (which now holds the next
                        // flow).
                        self.current_idx = if self.active_count == 0 {
                            0
                        } else {
                            idx % self.active_count
                        };
                    } else {
                        self.current_idx = (idx + 1) % self.active_count.max(1);
                    }
                    return Ok(len);
                }
            }
            attempts += 1;
        }
    }

    /// Advance the tick counter and perform perturbation if due.
    ///
    /// When the perturbation period elapses, the hash seed is
    /// changed.  This causes future packets to potentially map to
    /// different flow buckets, preventing persistent hash collisions.
    pub fn tick(&mut self) {
        self.current_tick = self.current_tick.wrapping_add(1);

        if self.perturbation_period > 0 && self.current_tick % self.perturbation_period == 0 {
            self.perturb();
        }
    }

    /// Return the total number of queued packets across all flows.
    pub fn total_queued(&self) -> usize {
        let mut total = 0usize;
        for flow in &self.flows {
            total += flow.len();
        }
        total
    }

    /// Return whether all flow queues are empty.
    pub fn is_empty(&self) -> bool {
        self.active_count == 0
    }

    // -- private helpers --

    /// Add a flow index to the active flows list.
    fn add_active_flow(&mut self, flow_idx: usize) {
        if self.active_count < MAX_ACTIVE_FLOWS {
            self.active_flows[self.active_count] = flow_idx;
            self.active_count += 1;
            self.stats.flows_active = self.active_count as u32;
        }
    }

    /// Remove a flow from the active flows list by its position in
    /// the list.
    fn remove_active_flow(&mut self, list_idx: usize) {
        if list_idx < self.active_count && self.active_count > 0 {
            // Shift remaining entries left.
            let mut i = list_idx;
            while i + 1 < self.active_count {
                self.active_flows[i] = self.active_flows[i + 1];
                i += 1;
            }
            self.active_count -= 1;
            self.stats.flows_active = self.active_count as u32;
        }
    }

    /// Re-seed the hash function for perturbation.
    fn perturb(&mut self) {
        // Simple deterministic perturbation: increment seed.
        self.hasher.seed = self.hasher.seed.wrapping_add(0xDEAD_BEEF);
        self.stats.perturbations = self.stats.perturbations.wrapping_add(1);
    }
}
