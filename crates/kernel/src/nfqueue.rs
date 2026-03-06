// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Netfilter userspace packet queue (NFQUEUE).
//!
//! Implements the NFQUEUE target for passing network packets to
//! userspace for verdict processing, modeled after the Linux
//! `net/netfilter/nfnetlink_queue.c` subsystem.
//!
//! # Overview
//!
//! NFQUEUE allows userspace applications to inspect, modify, and
//! render verdicts on packets that match netfilter rules. Packets
//! are enqueued with metadata (source interface, hook point,
//! protocol info) and a userspace handler provides a verdict:
//! accept, drop, repeat, or re-queue to another queue.
//!
//! # Queue Model
//!
//! - Queues are identified by a 16-bit queue number (0-65535)
//! - Each queue can have one bound handler at a time
//! - Packets waiting for a verdict are held in a fixed-size ring
//! - If the queue is full, new packets are dropped (fail-open or
//!   fail-close configurable)
//!
//! # Types
//!
//! - [`NfVerdict`] — packet verdict (accept, drop, repeat, queue)
//! - [`NfHook`] — netfilter hook point
//! - [`QueuedPacket`] — a packet waiting for a verdict
//! - [`NfQueue`] — a single netfilter queue instance
//! - [`NfQueueStats`] — per-queue statistics
//! - [`NfQueueRegistry`] — global registry of queues
//!
//! Reference: Linux `nfnetlink_queue`, `iptables -j NFQUEUE`

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum number of NFQUEUE instances in the system.
const MAX_QUEUES: usize = 64;

/// Maximum number of packets queued per NFQUEUE instance.
const MAX_PACKETS_PER_QUEUE: usize = 128;

/// Maximum packet payload size in bytes (for metadata storage).
const MAX_PACKET_PAYLOAD: usize = 256;

/// Maximum interface name length in bytes.
const MAX_IFNAME_LEN: usize = 16;

/// Maximum queue number (16-bit).
const MAX_QUEUE_NUM: u16 = u16::MAX;

// ── NfVerdict ──────────────────────────────────────────────────────

/// Netfilter packet verdict.
///
/// After inspecting a queued packet, the userspace handler issues
/// one of these verdicts to determine the packet's fate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfVerdict {
    /// Accept the packet and continue processing.
    Accept,
    /// Drop the packet silently.
    Drop,
    /// Re-inject the packet at the same hook point for
    /// re-evaluation.
    Repeat,
    /// Forward the packet to a different queue.
    Queue(u16),
}

impl Default for NfVerdict {
    fn default() -> Self {
        Self::Accept
    }
}

// ── NfHook ─────────────────────────────────────────────────────────

/// Netfilter hook point where the packet was intercepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfHook {
    /// Pre-routing (before routing decision).
    PreRouting,
    /// Local input (destined for this host).
    LocalIn,
    /// Forwarding (transiting through this host).
    Forward,
    /// Local output (originating from this host).
    LocalOut,
    /// Post-routing (after routing decision).
    PostRouting,
}

impl Default for NfHook {
    fn default() -> Self {
        Self::PreRouting
    }
}

// ── CopyMode ───────────────────────────────────────────────────────

/// How much of the packet payload to copy to userspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyMode {
    /// Do not copy any payload (metadata only).
    None,
    /// Copy up to a specified number of bytes.
    Packet(u32),
    /// Copy the entire packet.
    Full,
}

impl Default for CopyMode {
    fn default() -> Self {
        Self::Full
    }
}

// ── FailPolicy ─────────────────────────────────────────────────────

/// Policy when the queue is full and a new packet arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailPolicy {
    /// Accept the packet if the queue is full (fail-open).
    Accept,
    /// Drop the packet if the queue is full (fail-close).
    Drop,
}

impl Default for FailPolicy {
    fn default() -> Self {
        Self::Drop
    }
}

// ── QueuedPacket ───────────────────────────────────────────────────

/// A network packet queued for userspace verdict.
///
/// Contains packet metadata and a truncated payload snapshot for
/// inspection by the userspace handler.
#[derive(Debug, Clone, Copy)]
pub struct QueuedPacket {
    /// Unique packet ID within this queue (monotonically increasing).
    pub packet_id: u64,
    /// Netfilter hook point where the packet was intercepted.
    pub hook: NfHook,
    /// Ingress interface name (null-padded).
    pub indev: [u8; MAX_IFNAME_LEN],
    /// Ingress interface name length.
    pub indev_len: usize,
    /// Egress interface name (null-padded).
    pub outdev: [u8; MAX_IFNAME_LEN],
    /// Egress interface name length.
    pub outdev_len: usize,
    /// L3 protocol number (e.g., 0x0800 for IPv4).
    pub protocol: u16,
    /// Total packet length in bytes (original, before truncation).
    pub packet_len: u32,
    /// Truncated payload snapshot.
    pub payload: [u8; MAX_PACKET_PAYLOAD],
    /// Number of valid bytes in `payload`.
    pub payload_len: usize,
    /// Timestamp when the packet was queued (microseconds since
    /// boot).
    pub timestamp_us: u64,
    /// Mark value associated with the packet (for policy routing).
    pub mark: u32,
    /// Whether this slot is in use.
    pub in_use: bool,
    /// Whether a verdict has been rendered for this packet.
    pub verdict_set: bool,
    /// The verdict assigned to this packet.
    pub verdict: NfVerdict,
}

impl QueuedPacket {
    /// Creates an empty (inactive) packet slot.
    const fn empty() -> Self {
        Self {
            packet_id: 0,
            hook: NfHook::PreRouting,
            indev: [0u8; MAX_IFNAME_LEN],
            indev_len: 0,
            outdev: [0u8; MAX_IFNAME_LEN],
            outdev_len: 0,
            protocol: 0,
            packet_len: 0,
            payload: [0u8; MAX_PACKET_PAYLOAD],
            payload_len: 0,
            timestamp_us: 0,
            mark: 0,
            in_use: false,
            verdict_set: false,
            verdict: NfVerdict::Accept,
        }
    }
}

// ── NfQueueStats ───────────────────────────────────────────────────

/// Per-queue statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct NfQueueStats {
    /// Total number of packets enqueued.
    pub enqueued: u64,
    /// Total number of packets dequeued after verdict.
    pub dequeued: u64,
    /// Number of packets dropped due to full queue.
    pub dropped_full: u64,
    /// Number of packets dropped by userspace verdict.
    pub dropped_verdict: u64,
    /// Number of packets accepted by userspace verdict.
    pub accepted: u64,
    /// Number of packets repeated (re-injected).
    pub repeated: u64,
    /// Number of packets forwarded to another queue.
    pub requeued: u64,
    /// Current number of packets waiting for verdict.
    pub pending: u32,
    /// Peak number of packets waiting simultaneously.
    pub peak_pending: u32,
}

// ── NfQueue ────────────────────────────────────────────────────────

/// A single netfilter queue instance.
///
/// Holds queued packets, tracks the bound handler, and maintains
/// per-queue configuration and statistics.
#[derive(Debug, Clone, Copy)]
pub struct NfQueue {
    /// Queue number (0-65535).
    pub queue_num: u16,
    /// PID of the bound userspace handler (0 = unbound).
    pub handler_pid: u64,
    /// Queued packets awaiting verdict.
    packets: [QueuedPacket; MAX_PACKETS_PER_QUEUE],
    /// Number of packets currently queued.
    packet_count: usize,
    /// Next packet ID to assign.
    next_packet_id: u64,
    /// How much payload to copy to userspace.
    copy_mode: CopyMode,
    /// Policy when the queue is full.
    fail_policy: FailPolicy,
    /// Per-queue statistics.
    stats: NfQueueStats,
    /// Whether this queue slot is in use.
    pub in_use: bool,
    /// Whether this queue is actively accepting packets.
    pub enabled: bool,
}

impl NfQueue {
    /// Creates an empty (inactive) queue slot.
    const fn empty() -> Self {
        Self {
            queue_num: 0,
            handler_pid: 0,
            packets: [QueuedPacket::empty(); MAX_PACKETS_PER_QUEUE],
            packet_count: 0,
            next_packet_id: 1,
            copy_mode: CopyMode::Full,
            fail_policy: FailPolicy::Drop,
            stats: NfQueueStats {
                enqueued: 0,
                dequeued: 0,
                dropped_full: 0,
                dropped_verdict: 0,
                accepted: 0,
                repeated: 0,
                requeued: 0,
                pending: 0,
                peak_pending: 0,
            },
            in_use: false,
            enabled: false,
        }
    }

    /// Binds a userspace handler to this queue.
    ///
    /// Only one handler may be bound at a time.
    ///
    /// # Errors
    ///
    /// - `Error::InvalidArgument` — handler PID is zero.
    /// - `Error::Busy` — a handler is already bound.
    pub fn bind(&mut self, handler_pid: u64) -> Result<()> {
        if handler_pid == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.handler_pid != 0 {
            return Err(Error::Busy);
        }
        self.handler_pid = handler_pid;
        self.enabled = true;
        Ok(())
    }

    /// Unbinds the current handler from this queue.
    ///
    /// Any pending packets are dropped.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if no handler is bound.
    pub fn unbind(&mut self) -> Result<()> {
        if self.handler_pid == 0 {
            return Err(Error::NotFound);
        }

        // Drop all pending packets.
        for i in 0..MAX_PACKETS_PER_QUEUE {
            if self.packets[i].in_use {
                self.packets[i] = QueuedPacket::empty();
                self.stats.dropped_full = self.stats.dropped_full.saturating_add(1);
            }
        }
        self.packet_count = 0;
        self.stats.pending = 0;
        self.handler_pid = 0;
        self.enabled = false;
        Ok(())
    }

    /// Enqueues a packet for userspace verdict.
    ///
    /// Returns the assigned packet ID.
    ///
    /// # Errors
    ///
    /// - `Error::InvalidArgument` — no handler is bound.
    /// - `Error::OutOfMemory` — queue is full (after applying
    ///   fail-policy).
    pub fn enqueue(
        &mut self,
        hook: NfHook,
        indev: &[u8],
        outdev: &[u8],
        protocol: u16,
        payload: &[u8],
        timestamp_us: u64,
        mark: u32,
    ) -> Result<u64> {
        if self.handler_pid == 0 {
            return Err(Error::InvalidArgument);
        }

        if self.packet_count >= MAX_PACKETS_PER_QUEUE {
            self.stats.dropped_full = self.stats.dropped_full.saturating_add(1);
            return Err(Error::OutOfMemory);
        }

        // Find a free packet slot.
        let slot = self
            .packets
            .iter()
            .position(|p| !p.in_use)
            .ok_or(Error::OutOfMemory)?;

        let pkt = &mut self.packets[slot];
        *pkt = QueuedPacket::empty();

        let pkt_id = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.wrapping_add(1);

        pkt.packet_id = pkt_id;
        pkt.hook = hook;
        pkt.protocol = protocol;
        pkt.packet_len = payload.len() as u32;
        pkt.timestamp_us = timestamp_us;
        pkt.mark = mark;
        pkt.in_use = true;

        // Copy interface names (truncated to max length).
        let in_len = indev.len().min(MAX_IFNAME_LEN);
        pkt.indev[..in_len].copy_from_slice(&indev[..in_len]);
        pkt.indev_len = in_len;

        let out_len = outdev.len().min(MAX_IFNAME_LEN);
        pkt.outdev[..out_len].copy_from_slice(&outdev[..out_len]);
        pkt.outdev_len = out_len;

        // Copy payload according to copy mode.
        let copy_len = match self.copy_mode {
            CopyMode::None => 0,
            CopyMode::Packet(max_bytes) => payload.len().min(max_bytes as usize),
            CopyMode::Full => payload.len(),
        };
        let copy_len = copy_len.min(MAX_PACKET_PAYLOAD);
        pkt.payload[..copy_len].copy_from_slice(&payload[..copy_len]);
        pkt.payload_len = copy_len;

        self.packet_count += 1;
        self.stats.enqueued = self.stats.enqueued.saturating_add(1);
        self.stats.pending = self.packet_count as u32;

        if self.stats.pending > self.stats.peak_pending {
            self.stats.peak_pending = self.stats.pending;
        }

        Ok(pkt_id)
    }

    /// Sets a verdict on a queued packet.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — no packet with the given ID exists.
    /// - `Error::AlreadyExists` — a verdict was already set.
    pub fn set_verdict(&mut self, packet_id: u64, verdict: NfVerdict) -> Result<()> {
        let slot = self
            .packets
            .iter()
            .position(|p| p.in_use && p.packet_id == packet_id)
            .ok_or(Error::NotFound)?;

        if self.packets[slot].verdict_set {
            return Err(Error::AlreadyExists);
        }

        self.packets[slot].verdict = verdict;
        self.packets[slot].verdict_set = true;

        // Update statistics based on verdict.
        match verdict {
            NfVerdict::Accept => {
                self.stats.accepted = self.stats.accepted.saturating_add(1);
            }
            NfVerdict::Drop => {
                self.stats.dropped_verdict = self.stats.dropped_verdict.saturating_add(1);
            }
            NfVerdict::Repeat => {
                self.stats.repeated = self.stats.repeated.saturating_add(1);
            }
            NfVerdict::Queue(_) => {
                self.stats.requeued = self.stats.requeued.saturating_add(1);
            }
        }

        Ok(())
    }

    /// Dequeues a packet after a verdict has been set.
    ///
    /// Returns the verdict and removes the packet from the queue.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — no packet with the given ID exists.
    /// - `Error::WouldBlock` — verdict has not been set yet.
    pub fn dequeue(&mut self, packet_id: u64) -> Result<NfVerdict> {
        let slot = self
            .packets
            .iter()
            .position(|p| p.in_use && p.packet_id == packet_id)
            .ok_or(Error::NotFound)?;

        if !self.packets[slot].verdict_set {
            return Err(Error::WouldBlock);
        }

        let verdict = self.packets[slot].verdict;

        self.packets[slot] = QueuedPacket::empty();
        self.packet_count = self.packet_count.saturating_sub(1);
        self.stats.dequeued = self.stats.dequeued.saturating_add(1);
        self.stats.pending = self.packet_count as u32;

        Ok(verdict)
    }

    /// Returns a reference to a queued packet by ID.
    pub fn get_packet(&self, packet_id: u64) -> Option<&QueuedPacket> {
        self.packets
            .iter()
            .find(|p| p.in_use && p.packet_id == packet_id)
    }

    /// Drains all packets with set verdicts and returns the number
    /// of packets processed.
    pub fn drain_completed(&mut self) -> u32 {
        let mut drained = 0u32;

        for i in 0..MAX_PACKETS_PER_QUEUE {
            if self.packets[i].in_use && self.packets[i].verdict_set {
                self.packets[i] = QueuedPacket::empty();
                self.packet_count = self.packet_count.saturating_sub(1);
                self.stats.dequeued = self.stats.dequeued.saturating_add(1);
                drained += 1;
            }
        }

        self.stats.pending = self.packet_count as u32;
        drained
    }

    /// Sets the payload copy mode.
    pub fn set_copy_mode(&mut self, mode: CopyMode) {
        self.copy_mode = mode;
    }

    /// Returns the current copy mode.
    pub fn copy_mode(&self) -> CopyMode {
        self.copy_mode
    }

    /// Sets the fail policy for when the queue is full.
    pub fn set_fail_policy(&mut self, policy: FailPolicy) {
        self.fail_policy = policy;
    }

    /// Returns the current fail policy.
    pub fn fail_policy(&self) -> FailPolicy {
        self.fail_policy
    }

    /// Returns the number of packets currently queued.
    pub fn pending_count(&self) -> usize {
        self.packet_count
    }

    /// Returns a reference to the per-queue statistics.
    pub fn get_stats(&self) -> &NfQueueStats {
        &self.stats
    }

    /// Resets the statistics counters to zero.
    pub fn reset_stats(&mut self) {
        let pending = self.stats.pending;
        let peak = self.stats.peak_pending;
        self.stats = NfQueueStats::default();
        self.stats.pending = pending;
        self.stats.peak_pending = peak;
    }
}

// ── NfQueueRegistry ────────────────────────────────────────────────

/// Global registry of netfilter queue instances.
///
/// Manages up to [`MAX_QUEUES`] queues identified by queue number.
/// Provides centralized packet routing and verdict handling.
pub struct NfQueueRegistry {
    /// Fixed-size array of queue slots.
    queues: [NfQueue; MAX_QUEUES],
    /// Number of active queues.
    count: usize,
}

impl Default for NfQueueRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl NfQueueRegistry {
    /// Creates a new, empty queue registry.
    pub const fn new() -> Self {
        const EMPTY: NfQueue = NfQueue::empty();
        Self {
            queues: [EMPTY; MAX_QUEUES],
            count: 0,
        }
    }

    /// Returns the number of active queues.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no queues are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Creates a new queue with the given queue number.
    ///
    /// # Errors
    ///
    /// - `Error::AlreadyExists` — a queue with this number already
    ///   exists.
    /// - `Error::OutOfMemory` — no free slots available.
    pub fn create(&mut self, queue_num: u16) -> Result<()> {
        // Check for duplicate queue number.
        if self.find_queue(queue_num).is_some() {
            return Err(Error::AlreadyExists);
        }

        let slot = self
            .queues
            .iter()
            .position(|q| !q.in_use)
            .ok_or(Error::OutOfMemory)?;

        self.queues[slot] = NfQueue::empty();
        self.queues[slot].queue_num = queue_num;
        self.queues[slot].in_use = true;

        self.count += 1;
        Ok(())
    }

    /// Destroys a queue by queue number.
    ///
    /// All pending packets are dropped.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if no queue with the given number
    /// exists.
    pub fn destroy(&mut self, queue_num: u16) -> Result<()> {
        let idx = self.find_queue(queue_num).ok_or(Error::NotFound)?;

        self.queues[idx] = NfQueue::empty();
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Binds a userspace handler to a queue.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — queue does not exist.
    /// - `Error::InvalidArgument` — handler PID is zero.
    /// - `Error::Busy` — a handler is already bound.
    pub fn bind(&mut self, queue_num: u16, handler_pid: u64) -> Result<()> {
        let idx = self.find_queue(queue_num).ok_or(Error::NotFound)?;
        self.queues[idx].bind(handler_pid)
    }

    /// Unbinds the handler from a queue.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — queue does not exist or no handler
    ///   bound.
    pub fn unbind(&mut self, queue_num: u16) -> Result<()> {
        let idx = self.find_queue(queue_num).ok_or(Error::NotFound)?;
        self.queues[idx].unbind()
    }

    /// Enqueues a packet to the specified queue.
    ///
    /// Returns the assigned packet ID.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — queue does not exist.
    /// - `Error::InvalidArgument` — queue has no bound handler.
    /// - `Error::OutOfMemory` — queue is full.
    pub fn enqueue_packet(
        &mut self,
        queue_num: u16,
        hook: NfHook,
        indev: &[u8],
        outdev: &[u8],
        protocol: u16,
        payload: &[u8],
        timestamp_us: u64,
        mark: u32,
    ) -> Result<u64> {
        let idx = self.find_queue(queue_num).ok_or(Error::NotFound)?;

        let queue = &mut self.queues[idx];

        // Apply fail policy if queue is full.
        if queue.packet_count >= MAX_PACKETS_PER_QUEUE {
            match queue.fail_policy {
                FailPolicy::Accept => {
                    queue.stats.dropped_full = queue.stats.dropped_full.saturating_add(1);
                    // Fail-open: caller should accept the packet.
                    return Err(Error::WouldBlock);
                }
                FailPolicy::Drop => {
                    queue.stats.dropped_full = queue.stats.dropped_full.saturating_add(1);
                    return Err(Error::OutOfMemory);
                }
            }
        }

        queue.enqueue(hook, indev, outdev, protocol, payload, timestamp_us, mark)
    }

    /// Sets a verdict on a queued packet.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — queue or packet not found.
    /// - `Error::AlreadyExists` — verdict already set.
    pub fn set_verdict(
        &mut self,
        queue_num: u16,
        packet_id: u64,
        verdict: NfVerdict,
    ) -> Result<()> {
        let idx = self.find_queue(queue_num).ok_or(Error::NotFound)?;
        self.queues[idx].set_verdict(packet_id, verdict)
    }

    /// Dequeues a packet after its verdict has been set.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — queue or packet not found.
    /// - `Error::WouldBlock` — verdict not yet set.
    pub fn dequeue_packet(&mut self, queue_num: u16, packet_id: u64) -> Result<NfVerdict> {
        let idx = self.find_queue(queue_num).ok_or(Error::NotFound)?;
        self.queues[idx].dequeue(packet_id)
    }

    /// Returns an immutable reference to a queue by number.
    pub fn get(&self, queue_num: u16) -> Option<&NfQueue> {
        self.find_queue(queue_num).map(|idx| &self.queues[idx])
    }

    /// Returns a mutable reference to a queue by number.
    pub fn get_mut(&mut self, queue_num: u16) -> Option<&mut NfQueue> {
        self.find_queue(queue_num).map(|idx| &mut self.queues[idx])
    }

    /// Returns the total number of pending packets across all
    /// queues.
    pub fn total_pending(&self) -> usize {
        let mut total = 0usize;
        for queue in &self.queues {
            if queue.in_use {
                total = total.saturating_add(queue.packet_count);
            }
        }
        total
    }

    // ── Internal helpers ───────────────────────────────────────────

    /// Finds a queue by queue number and returns its slot index.
    fn find_queue(&self, queue_num: u16) -> Option<usize> {
        self.queues
            .iter()
            .position(|q| q.in_use && q.queue_num == queue_num)
    }
}
