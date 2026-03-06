// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Expedited RCU grace periods.
//!
//! Provides a fast-path RCU synchronisation mechanism that trades
//! higher CPU cost for lower latency. Instead of waiting for each
//! CPU to pass through a quiescent state naturally (which may take
//! milliseconds), expedited RCU sends IPIs to force an immediate
//! quiescent state on every CPU.
//!
//! # When to Use
//!
//! - Module unload (must complete quickly).
//! - Memory reclaim under pressure.
//! - Situations where the normal grace period is too slow.
//!
//! # Design
//!
//! ```text
//! RcuExpedited
//!  ├── generation: u64
//!  ├── state: ExpediteState
//!  ├── cpu_acks: [CpuAck; MAX_CPUS]
//!  └── stats: ExpeditedStats
//! ```
//!
//! An expedited grace period proceeds as follows:
//! 1. Increment generation and record the set of online CPUs.
//! 2. Send an IPI to each online CPU.
//! 3. Each CPU's IPI handler notes a quiescent state and acks.
//! 4. When all CPUs have acked, the grace period is complete.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum CPUs.
const MAX_CPUS: usize = 64;

/// Maximum concurrent expedited operations.
const MAX_EXPEDITED: usize = 8;

/// Timeout for expedited grace period (ticks).
const _EXPEDITE_TIMEOUT_TICKS: u64 = 5_000;

// ======================================================================
// Types
// ======================================================================

/// State of an expedited grace period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpediteState {
    /// No expedited operation in progress.
    Idle,
    /// IPIs have been sent; waiting for acks.
    WaitingForAcks,
    /// All CPUs have acknowledged.
    Completed,
    /// Timed out waiting for one or more CPUs.
    TimedOut,
}

impl Default for ExpediteState {
    fn default() -> Self {
        Self::Idle
    }
}

/// Per-CPU acknowledgement state.
#[derive(Debug, Clone, Copy)]
pub struct CpuAck {
    /// CPU identifier.
    pub cpu_id: u32,
    /// Whether this CPU needs to ack.
    pub pending: bool,
    /// Whether this CPU has acknowledged.
    pub acked: bool,
    /// Tick at which the IPI was sent.
    pub ipi_sent_tick: u64,
    /// Tick at which the ack was received.
    pub ack_tick: u64,
}

impl CpuAck {
    /// Creates an idle CPU ack entry.
    pub const fn new() -> Self {
        Self {
            cpu_id: 0,
            pending: false,
            acked: false,
            ipi_sent_tick: 0,
            ack_tick: 0,
        }
    }
}

impl Default for CpuAck {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for expedited RCU operations.
#[derive(Debug, Clone, Copy)]
pub struct ExpeditedStats {
    /// Total expedited grace periods requested.
    pub total_requests: u64,
    /// Completed within timeout.
    pub completed: u64,
    /// Timed out.
    pub timeouts: u64,
    /// Total IPIs sent.
    pub ipis_sent: u64,
    /// Total acks received.
    pub acks_received: u64,
    /// Fastest completion time (ticks).
    pub fastest_ticks: u64,
    /// Slowest completion time (ticks).
    pub slowest_ticks: u64,
}

impl ExpeditedStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_requests: 0,
            completed: 0,
            timeouts: 0,
            ipis_sent: 0,
            acks_received: 0,
            fastest_ticks: u64::MAX,
            slowest_ticks: 0,
        }
    }
}

impl Default for ExpeditedStats {
    fn default() -> Self {
        Self::new()
    }
}

/// A single expedited grace period operation.
#[derive(Debug, Clone, Copy)]
pub struct ExpeditedOp {
    /// Generation number.
    pub generation: u64,
    /// Current state.
    pub state: ExpediteState,
    /// Number of CPUs that must ack.
    pub target_count: u32,
    /// Number of CPUs that have acked.
    pub ack_count: u32,
    /// Tick when the operation started.
    pub start_tick: u64,
    /// Whether this slot is in use.
    pub active: bool,
}

impl ExpeditedOp {
    /// Creates an empty operation.
    pub const fn new() -> Self {
        Self {
            generation: 0,
            state: ExpediteState::Idle,
            target_count: 0,
            ack_count: 0,
            start_tick: 0,
            active: false,
        }
    }
}

impl Default for ExpeditedOp {
    fn default() -> Self {
        Self::new()
    }
}

/// Expedited RCU subsystem.
pub struct RcuExpedited {
    /// Generation counter.
    generation: u64,
    /// Per-CPU ack tracking.
    cpu_acks: [CpuAck; MAX_CPUS],
    /// Number of online CPUs.
    nr_cpus: u32,
    /// Concurrent expedited operations.
    ops: [ExpeditedOp; MAX_EXPEDITED],
    /// Number of active operations.
    nr_active: usize,
    /// Statistics.
    stats: ExpeditedStats,
}

impl RcuExpedited {
    /// Creates a new expedited RCU subsystem.
    pub const fn new() -> Self {
        Self {
            generation: 0,
            cpu_acks: [CpuAck::new(); MAX_CPUS],
            nr_cpus: 1,
            ops: [ExpeditedOp::new(); MAX_EXPEDITED],
            nr_active: 0,
            stats: ExpeditedStats::new(),
        }
    }

    /// Sets the number of online CPUs.
    pub fn set_nr_cpus(&mut self, nr: u32) -> Result<()> {
        if nr == 0 || (nr as usize) > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.nr_cpus = nr;
        for i in 0..(nr as usize) {
            self.cpu_acks[i].cpu_id = i as u32;
        }
        Ok(())
    }

    /// Starts a new expedited grace period.
    ///
    /// Returns the generation number of the new operation.
    pub fn start(&mut self, current_tick: u64) -> Result<u64> {
        if self.nr_active >= MAX_EXPEDITED {
            return Err(Error::Busy);
        }
        self.generation = self.generation.wrapping_add(1);
        let cur_gen = self.generation;

        // Reset per-CPU ack state.
        for i in 0..(self.nr_cpus as usize) {
            self.cpu_acks[i].pending = true;
            self.cpu_acks[i].acked = false;
            self.cpu_acks[i].ipi_sent_tick = current_tick;
            self.cpu_acks[i].ack_tick = 0;
        }

        // Allocate an operation slot.
        for op in &mut self.ops {
            if !op.active {
                *op = ExpeditedOp {
                    generation: cur_gen,
                    state: ExpediteState::WaitingForAcks,
                    target_count: self.nr_cpus,
                    ack_count: 0,
                    start_tick: current_tick,
                    active: true,
                };
                self.nr_active += 1;
                self.stats.total_requests += 1;
                self.stats.ipis_sent += self.nr_cpus as u64;
                return Ok(cur_gen);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Records an acknowledgement from a CPU.
    pub fn ack_cpu(&mut self, cpu_id: u32, generation: u64, current_tick: u64) -> Result<bool> {
        if (cpu_id as usize) >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let ack = &mut self.cpu_acks[cpu_id as usize];
        if !ack.pending || ack.acked {
            return Ok(false);
        }
        ack.acked = true;
        ack.pending = false;
        ack.ack_tick = current_tick;
        self.stats.acks_received += 1;

        // Find the matching operation and update.
        for op in &mut self.ops {
            if op.active && op.generation == generation {
                op.ack_count += 1;
                if op.ack_count >= op.target_count {
                    op.state = ExpediteState::Completed;
                    op.active = false;
                    self.nr_active = self.nr_active.saturating_sub(1);
                    self.stats.completed += 1;

                    let elapsed = current_tick.wrapping_sub(op.start_tick);
                    if elapsed < self.stats.fastest_ticks {
                        self.stats.fastest_ticks = elapsed;
                    }
                    if elapsed > self.stats.slowest_ticks {
                        self.stats.slowest_ticks = elapsed;
                    }
                    return Ok(true); // grace period complete
                }
                return Ok(false);
            }
        }
        Err(Error::NotFound)
    }

    /// Checks for timed-out operations.
    pub fn check_timeouts(&mut self, current_tick: u64) -> u32 {
        let mut timed_out = 0u32;
        for op in &mut self.ops {
            if op.active
                && op.state == ExpediteState::WaitingForAcks
                && current_tick.wrapping_sub(op.start_tick) > _EXPEDITE_TIMEOUT_TICKS
            {
                op.state = ExpediteState::TimedOut;
                op.active = false;
                self.nr_active = self.nr_active.saturating_sub(1);
                self.stats.timeouts += 1;
                timed_out += 1;
            }
        }
        timed_out
    }

    /// Returns the current generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns statistics.
    pub fn stats(&self) -> &ExpeditedStats {
        &self.stats
    }

    /// Returns the number of active operations.
    pub fn nr_active(&self) -> usize {
        self.nr_active
    }
}

impl Default for RcuExpedited {
    fn default() -> Self {
        Self::new()
    }
}
