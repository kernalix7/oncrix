// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RCU barrier synchronisation.
//!
//! Provides the `rcu_barrier()` primitive that waits until all
//! previously posted RCU callbacks on every CPU have been invoked.
//! This is used when a kernel module is being unloaded to guarantee
//! that no callback references stale module code.
//!
//! # Design
//!
//! ```text
//! RcuBarrier (global coordinator)
//!  ├── target_count: u32   (total CPUs that must report)
//!  ├── completed: u32      (CPUs that finished callbacks)
//!  ├── state: BarrierState
//!  └── PerCpuBarrier[MAX_CPUS]
//!       ├── pending: bool
//!       └── generation: u64
//! ```
//!
//! Each CPU enqueues a special barrier callback. When every such
//! callback has executed the barrier is released.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum CPUs supported.
const MAX_CPUS: usize = 64;

/// Maximum concurrent barrier operations.
const MAX_BARRIERS: usize = 8;

/// Timeout in ticks for a barrier wait before considering a CPU hung.
const _BARRIER_TIMEOUT_TICKS: u64 = 10_000;

// ======================================================================
// Types
// ======================================================================

/// State of a barrier operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarrierState {
    /// No barrier in progress.
    Idle,
    /// Barrier callbacks have been enqueued, waiting for completion.
    Pending,
    /// All CPUs have completed their barrier callbacks.
    Completed,
    /// The barrier timed out waiting for one or more CPUs.
    TimedOut,
}

impl Default for BarrierState {
    fn default() -> Self {
        Self::Idle
    }
}

/// Per-CPU barrier tracking information.
#[derive(Debug, Clone, Copy)]
pub struct PerCpuBarrier {
    /// Whether this CPU has a pending barrier callback.
    pub pending: bool,
    /// The generation this CPU is synchronising against.
    pub generation: u64,
    /// Tick at which the barrier callback was enqueued.
    pub enqueue_tick: u64,
    /// Whether the barrier callback has completed on this CPU.
    pub completed: bool,
}

impl PerCpuBarrier {
    /// Creates a new idle per-CPU barrier entry.
    pub const fn new() -> Self {
        Self {
            pending: false,
            generation: 0,
            enqueue_tick: 0,
            completed: false,
        }
    }
}

impl Default for PerCpuBarrier {
    fn default() -> Self {
        Self::new()
    }
}

/// Global RCU barrier coordinator.
///
/// Manages the synchronisation required to ensure all CPUs have
/// completed their pending RCU callbacks before the barrier returns.
pub struct RcuBarrier {
    /// Current barrier generation number.
    generation: u64,
    /// Number of CPUs that must report completion.
    target_count: u32,
    /// Number of CPUs that have completed their barrier callback.
    completed_count: u32,
    /// Current state of the barrier.
    state: BarrierState,
    /// Per-CPU barrier state.
    per_cpu: [PerCpuBarrier; MAX_CPUS],
    /// Number of online CPUs.
    online_cpus: u32,
}

impl RcuBarrier {
    /// Creates a new RCU barrier coordinator.
    pub const fn new() -> Self {
        Self {
            generation: 0,
            target_count: 0,
            completed_count: 0,
            state: BarrierState::Idle,
            per_cpu: [PerCpuBarrier::new(); MAX_CPUS],
            online_cpus: 1,
        }
    }

    /// Sets the number of online CPUs for barrier tracking.
    pub fn set_online_cpus(&mut self, count: u32) -> Result<()> {
        if count == 0 || (count as usize) > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.online_cpus = count;
        Ok(())
    }

    /// Initiates a new barrier operation.
    ///
    /// Enqueues a barrier callback on every online CPU. The barrier
    /// completes when all CPUs have executed their callback.
    pub fn initiate(&mut self, current_tick: u64) -> Result<u64> {
        if self.state == BarrierState::Pending {
            return Err(Error::Busy);
        }
        self.generation = self.generation.wrapping_add(1);
        self.target_count = self.online_cpus;
        self.completed_count = 0;
        self.state = BarrierState::Pending;

        for i in 0..(self.online_cpus as usize) {
            self.per_cpu[i] = PerCpuBarrier {
                pending: true,
                generation: self.generation,
                enqueue_tick: current_tick,
                completed: false,
            };
        }
        Ok(self.generation)
    }

    /// Reports completion of a barrier callback on a specific CPU.
    pub fn report_cpu_complete(&mut self, cpu_id: u32, generation: u64) -> Result<bool> {
        if (cpu_id as usize) >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let entry = &mut self.per_cpu[cpu_id as usize];
        if entry.generation != generation {
            return Err(Error::InvalidArgument);
        }
        if entry.completed {
            return Ok(false);
        }
        entry.completed = true;
        entry.pending = false;
        self.completed_count += 1;

        if self.completed_count >= self.target_count {
            self.state = BarrierState::Completed;
            return Ok(true);
        }
        Ok(false)
    }

    /// Returns the current barrier state.
    pub fn state(&self) -> BarrierState {
        self.state
    }

    /// Returns the current generation number.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Resets the barrier to idle state after completion.
    pub fn reset(&mut self) -> Result<()> {
        if self.state == BarrierState::Pending {
            return Err(Error::Busy);
        }
        self.state = BarrierState::Idle;
        self.completed_count = 0;
        self.target_count = 0;
        Ok(())
    }

    /// Checks whether the barrier has timed out.
    ///
    /// If any CPU has not completed its callback within the timeout
    /// window, transitions to `TimedOut` state.
    pub fn check_timeout(&mut self, current_tick: u64) -> bool {
        if self.state != BarrierState::Pending {
            return false;
        }
        for i in 0..(self.online_cpus as usize) {
            let entry = &self.per_cpu[i];
            if entry.pending
                && !entry.completed
                && current_tick.wrapping_sub(entry.enqueue_tick) > _BARRIER_TIMEOUT_TICKS
            {
                self.state = BarrierState::TimedOut;
                return true;
            }
        }
        false
    }
}

impl Default for RcuBarrier {
    fn default() -> Self {
        Self::new()
    }
}

/// Barrier registry tracking multiple concurrent barrier operations.
pub struct BarrierRegistry {
    /// Active barriers.
    barriers: [Option<RcuBarrier>; MAX_BARRIERS],
    /// Number of active barriers.
    active_count: usize,
}

impl BarrierRegistry {
    /// Creates a new empty barrier registry.
    pub const fn new() -> Self {
        Self {
            barriers: [const { None }; MAX_BARRIERS],
            active_count: 0,
        }
    }

    /// Allocates a new barrier slot.
    pub fn allocate(&mut self) -> Result<usize> {
        if self.active_count >= MAX_BARRIERS {
            return Err(Error::OutOfMemory);
        }
        for (i, slot) in self.barriers.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(RcuBarrier::new());
                self.active_count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Releases a barrier slot.
    pub fn release(&mut self, index: usize) -> Result<()> {
        if index >= MAX_BARRIERS {
            return Err(Error::InvalidArgument);
        }
        if self.barriers[index].is_none() {
            return Err(Error::NotFound);
        }
        self.barriers[index] = None;
        self.active_count = self.active_count.saturating_sub(1);
        Ok(())
    }

    /// Returns the number of active barriers.
    pub fn active_count(&self) -> usize {
        self.active_count
    }
}

impl Default for BarrierRegistry {
    fn default() -> Self {
        Self::new()
    }
}
