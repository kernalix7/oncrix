// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! I/O scheduler (elevator) — noop, deadline, and round-robin policies.
//!
//! The I/O elevator orders and merges block I/O requests before they are
//! dispatched to the device. This module implements three classic policies:
//!
//! - **Noop** — FIFO order, no reordering. Best for SSDs and random-access.
//! - **Deadline** — Bounded latency: reads expire after 500 ms, writes after
//!   5 s. Prevents starvation while allowing some sorting.
//! - **RoundRobin** — Alternates between read and write batches.
//!
//! # References
//!
//! - Linux `blk-noop.c`, `blk-mq-sched.c`, `deadline-iosched.c`
//! - Linux kernel docs: `Documentation/block/iosched.rst`

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of requests in the elevator queue.
pub const ELEVATOR_QUEUE_DEPTH: usize = 256;

/// Deadline: read request expiry (ms).
pub const DEADLINE_READ_EXPIRE_MS: u64 = 500;

/// Deadline: write request expiry (ms).
pub const DEADLINE_WRITE_EXPIRE_MS: u64 = 5_000;

// ── ElevatorPolicy ───────────────────────────────────────────────────

/// The scheduling policy to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElevatorPolicy {
    /// FIFO — no reordering.
    Noop,
    /// Deadline — expiry-bounded FIFO.
    Deadline,
    /// Round-robin between reads and writes.
    RoundRobin,
}

// ── ElevReq ──────────────────────────────────────────────────────────

/// A request in the elevator queue.
#[derive(Clone, Copy)]
pub struct ElevReq {
    /// Request ID (from the bio layer).
    pub id: u64,
    /// Starting sector.
    pub sector: u64,
    /// Number of sectors.
    pub nr_sectors: u32,
    /// `true` for read, `false` for write.
    pub is_read: bool,
    /// Submission timestamp (ms, monotonic).
    pub submitted_ms: u64,
    /// Deadline (ms, monotonic). `0` means no deadline.
    pub deadline_ms: u64,
    /// Whether this slot is active.
    pub active: bool,
}

impl ElevReq {
    /// Create a new elevator request.
    pub const fn new(
        id: u64,
        sector: u64,
        nr_sectors: u32,
        is_read: bool,
        now_ms: u64,
        policy: ElevatorPolicy,
    ) -> Self {
        let deadline_ms = match policy {
            ElevatorPolicy::Deadline => {
                if is_read {
                    now_ms + DEADLINE_READ_EXPIRE_MS
                } else {
                    now_ms + DEADLINE_WRITE_EXPIRE_MS
                }
            }
            _ => 0,
        };
        Self {
            id,
            sector,
            nr_sectors,
            is_read,
            submitted_ms: now_ms,
            deadline_ms,
            active: true,
        }
    }

    /// Returns `true` if the deadline has expired.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        self.deadline_ms > 0 && now_ms >= self.deadline_ms
    }
}

// ── Elevator ─────────────────────────────────────────────────────────

/// An I/O elevator/scheduler instance for one device.
pub struct Elevator {
    /// Scheduling policy.
    pub policy: ElevatorPolicy,
    /// Request queue.
    queue: [Option<ElevReq>; ELEVATOR_QUEUE_DEPTH],
    count: usize,
    /// Round-robin state: `true` = favour reads next.
    rr_reads_turn: bool,
}

impl Elevator {
    /// Create a new elevator with the given policy.
    pub const fn new(policy: ElevatorPolicy) -> Self {
        Self {
            policy,
            queue: [const { None }; ELEVATOR_QUEUE_DEPTH],
            count: 0,
            rr_reads_turn: true,
        }
    }

    /// Enqueue a request.
    pub fn enqueue(
        &mut self,
        id: u64,
        sector: u64,
        nr_sectors: u32,
        is_read: bool,
        now_ms: u64,
    ) -> Result<()> {
        if self.count >= ELEVATOR_QUEUE_DEPTH {
            return Err(Error::OutOfMemory);
        }
        let req = ElevReq::new(id, sector, nr_sectors, is_read, now_ms, self.policy);
        for slot in self.queue.iter_mut() {
            if slot.is_none() {
                *slot = Some(req);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Dispatch the next request according to the current policy.
    ///
    /// Returns the dispatched request, or `None` if the queue is empty.
    pub fn dispatch(&mut self, now_ms: u64) -> Option<ElevReq> {
        if self.count == 0 {
            return None;
        }
        match self.policy {
            ElevatorPolicy::Noop => self.dispatch_noop(),
            ElevatorPolicy::Deadline => self.dispatch_deadline(now_ms),
            ElevatorPolicy::RoundRobin => self.dispatch_rr(now_ms),
        }
    }

    // -- Noop: FIFO — take the first active request.
    fn dispatch_noop(&mut self) -> Option<ElevReq> {
        for slot in self.queue.iter_mut() {
            if let Some(req) = slot.take() {
                self.count = self.count.saturating_sub(1);
                return Some(req);
            }
        }
        None
    }

    // -- Deadline: prefer expired requests; otherwise FIFO.
    fn dispatch_deadline(&mut self, now_ms: u64) -> Option<ElevReq> {
        // First pass: pick any expired request.
        for slot in self.queue.iter_mut() {
            if let Some(req) = slot {
                if req.active && req.is_expired(now_ms) {
                    let r = *req;
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                    return Some(r);
                }
            }
        }
        // Second pass: FIFO.
        self.dispatch_noop()
    }

    // -- Round-robin: alternate read/write batches.
    fn dispatch_rr(&mut self, now_ms: u64) -> Option<ElevReq> {
        // Try to dispatch a request matching the current preference.
        for pass in 0..2u32 {
            let want_read = if pass == 0 {
                self.rr_reads_turn
            } else {
                !self.rr_reads_turn
            };
            for slot in self.queue.iter_mut() {
                if let Some(req) = slot {
                    if req.active && req.is_read == want_read {
                        let r = *req;
                        *slot = None;
                        self.count = self.count.saturating_sub(1);
                        // Flip preference after dispatching.
                        self.rr_reads_turn = !self.rr_reads_turn;
                        return Some(r);
                    }
                }
            }
        }
        // Fall back to noop if no requests of either type exist.
        let _ = now_ms;
        self.dispatch_noop()
    }

    /// Cancel a request by ID.
    pub fn cancel(&mut self, id: u64) -> Result<()> {
        for slot in self.queue.iter_mut() {
            if let Some(req) = slot {
                if req.id == id {
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of queued requests.
    pub fn depth(&self) -> usize {
        self.count
    }

    /// Returns `true` if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Merge-check: return `true` if `sector` is adjacent to an existing request.
    pub fn can_merge(&self, sector: u64, is_read: bool) -> bool {
        for slot in self.queue.iter() {
            if let Some(req) = slot {
                if req.is_read == is_read {
                    let end = req.sector + req.nr_sectors as u64;
                    if end == sector || sector + 0 == req.sector {
                        return true;
                    }
                }
            }
        }
        false
    }
}

// ── ElevatorSet ──────────────────────────────────────────────────────

/// Maximum number of devices with an elevator.
pub const MAX_ELEVATOR_DEVS: usize = 16;

/// System-wide elevator registry.
pub struct ElevatorSet {
    elevators: [Option<(u32, Elevator)>; MAX_ELEVATOR_DEVS],
    count: usize,
}

impl ElevatorSet {
    /// Create an empty elevator set.
    pub const fn new() -> Self {
        Self {
            elevators: [const { None }; MAX_ELEVATOR_DEVS],
            count: 0,
        }
    }

    /// Register a new elevator for `dev` with the given policy.
    pub fn register(&mut self, dev: u32, policy: ElevatorPolicy) -> Result<()> {
        for slot in self.elevators.iter() {
            if let Some((d, _)) = slot {
                if *d == dev {
                    return Err(Error::AlreadyExists);
                }
            }
        }
        if self.count >= MAX_ELEVATOR_DEVS {
            return Err(Error::OutOfMemory);
        }
        for slot in self.elevators.iter_mut() {
            if slot.is_none() {
                *slot = Some((dev, Elevator::new(policy)));
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Enqueue a request on the elevator for `dev`.
    pub fn enqueue(
        &mut self,
        dev: u32,
        id: u64,
        sector: u64,
        nr_sectors: u32,
        is_read: bool,
        now_ms: u64,
    ) -> Result<()> {
        for slot in self.elevators.iter_mut() {
            if let Some((d, el)) = slot {
                if *d == dev {
                    return el.enqueue(id, sector, nr_sectors, is_read, now_ms);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Dispatch the next request for `dev`.
    pub fn dispatch(&mut self, dev: u32, now_ms: u64) -> Option<ElevReq> {
        for slot in self.elevators.iter_mut() {
            if let Some((d, el)) = slot {
                if *d == dev {
                    return el.dispatch(now_ms);
                }
            }
        }
        None
    }
}

impl Default for ElevatorSet {
    fn default() -> Self {
        Self::new()
    }
}
// Global operations performed through owned instance, avoiding static mut.
