// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Read-Copy-Update (RCU) core implementation.
//!
//! Provides the fundamental RCU synchronisation mechanism: readers
//! proceed lock-free while writers defer reclamation until all
//! pre-existing readers have completed their critical sections.
//!
//! # Architecture
//!
//! ```text
//! RcuState (global)
//!  ├── grace_period: u64  (monotonically increasing)
//!  ├── completed: u64     (last completed GP)
//!  ├── PerCpuRcu[MAX_CPUS]
//!  │    ├── nesting: i32  (read-side nesting depth)
//!  │    ├── qs_passed: bool (quiescent state seen)
//!  │    └── callbacks: [RcuCallback; MAX_CBS]
//!  └── RcuStats
//! ```
//!
//! A quiescent state is a point where a CPU is guaranteed not to
//! hold any RCU read-side references (e.g., context switch, idle).

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum CPUs.
const MAX_CPUS: usize = 64;

/// Maximum pending RCU callbacks per CPU.
const MAX_CALLBACKS: usize = 128;

/// Maximum callback data size in bytes.
const _CB_DATA_SIZE: usize = 8;

// ======================================================================
// Types
// ======================================================================

/// An RCU callback to be invoked after a grace period.
#[derive(Clone, Copy)]
pub struct RcuCallback {
    /// Callback identifier (application-defined).
    pub id: u64,
    /// Data associated with the callback.
    pub data: u64,
    /// Grace period number after which this callback can fire.
    pub gp_seq: u64,
    /// Whether this slot is used.
    pub active: bool,
}

impl RcuCallback {
    /// Creates an inactive callback slot.
    pub const fn new() -> Self {
        Self {
            id: 0,
            data: 0,
            gp_seq: 0,
            active: false,
        }
    }
}

/// Per-CPU RCU state.
pub struct PerCpuRcu {
    /// Read-side nesting depth. Positive means inside an RCU
    /// read-side critical section.
    pub nesting: i32,
    /// Whether a quiescent state has been observed since the
    /// current grace period started.
    pub qs_passed: bool,
    /// Pending callbacks.
    callbacks: [RcuCallback; MAX_CALLBACKS],
    /// Number of pending callbacks.
    pub nr_callbacks: usize,
    /// Number of callbacks invoked.
    pub nr_invoked: u64,
    /// Whether this CPU is online.
    pub online: bool,
}

impl PerCpuRcu {
    /// Creates per-CPU RCU state.
    pub const fn new() -> Self {
        Self {
            nesting: 0,
            qs_passed: false,
            callbacks: [const { RcuCallback::new() }; MAX_CALLBACKS],
            nr_callbacks: 0,
            nr_invoked: 0,
            online: false,
        }
    }

    /// Enters an RCU read-side critical section.
    /// Increments nesting depth.
    pub fn rcu_read_lock(&mut self) {
        self.nesting += 1;
    }

    /// Exits an RCU read-side critical section.
    /// Decrements nesting depth. When it reaches zero, a quiescent
    /// state is recorded.
    pub fn rcu_read_unlock(&mut self) {
        self.nesting -= 1;
        if self.nesting == 0 {
            self.qs_passed = true;
        }
    }

    /// Returns `true` if inside an RCU read-side critical section.
    pub fn in_read_side(&self) -> bool {
        self.nesting > 0
    }

    /// Registers a deferred callback.
    pub fn call_rcu(&mut self, id: u64, data: u64, gp_seq: u64) -> Result<()> {
        let slot = self
            .callbacks
            .iter()
            .position(|c| !c.active)
            .ok_or(Error::OutOfMemory)?;
        self.callbacks[slot].id = id;
        self.callbacks[slot].data = data;
        self.callbacks[slot].gp_seq = gp_seq;
        self.callbacks[slot].active = true;
        self.nr_callbacks += 1;
        Ok(())
    }

    /// Processes callbacks whose grace period has completed.
    /// Returns the number of callbacks invoked.
    pub fn process_callbacks(&mut self, completed_gp: u64) -> u32 {
        let mut count = 0u32;
        for cb in &mut self.callbacks {
            if cb.active && cb.gp_seq <= completed_gp {
                cb.active = false;
                self.nr_callbacks = self.nr_callbacks.saturating_sub(1);
                self.nr_invoked += 1;
                count += 1;
            }
        }
        count
    }

    /// Reports a quiescent state (e.g., context switch or idle).
    pub fn report_qs(&mut self) {
        if self.nesting == 0 {
            self.qs_passed = true;
        }
    }
}

// ======================================================================
// RCU statistics
// ======================================================================

/// Global RCU statistics.
pub struct RcuStats {
    /// Number of grace periods completed.
    pub gp_completed: u64,
    /// Number of grace periods started.
    pub gp_started: u64,
    /// Total callbacks invoked across all CPUs.
    pub total_callbacks_invoked: u64,
    /// Total callbacks registered.
    pub total_callbacks_registered: u64,
    /// Number of forced quiescent states.
    pub nr_forced_qs: u64,
}

impl RcuStats {
    /// Creates zeroed stats.
    pub const fn new() -> Self {
        Self {
            gp_completed: 0,
            gp_started: 0,
            total_callbacks_invoked: 0,
            total_callbacks_registered: 0,
            nr_forced_qs: 0,
        }
    }
}

// ======================================================================
// RcuState — global
// ======================================================================

/// Global RCU state.
pub struct RcuState {
    /// Current grace period sequence number.
    pub gp_seq: u64,
    /// Last completed grace period.
    pub completed: u64,
    /// Per-CPU RCU state.
    cpus: [PerCpuRcu; MAX_CPUS],
    /// Number of online CPUs.
    pub nr_cpus: u32,
    /// Statistics.
    pub stats: RcuStats,
    /// Whether a grace period is in progress.
    pub gp_in_progress: bool,
}

impl RcuState {
    /// Creates the global RCU state.
    pub const fn new() -> Self {
        Self {
            gp_seq: 0,
            completed: 0,
            cpus: [const { PerCpuRcu::new() }; MAX_CPUS],
            nr_cpus: 1,
            stats: RcuStats::new(),
            gp_in_progress: false,
        }
    }

    /// Brings a CPU online for RCU.
    pub fn cpu_online(&mut self, cpu: u32) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.cpus[c].online = true;
        if cpu >= self.nr_cpus {
            self.nr_cpus = cpu + 1;
        }
        Ok(())
    }

    /// Enters an RCU read-side critical section on the given CPU.
    pub fn rcu_read_lock(&mut self, cpu: u32) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS || !self.cpus[c].online {
            return Err(Error::InvalidArgument);
        }
        self.cpus[c].rcu_read_lock();
        Ok(())
    }

    /// Exits an RCU read-side critical section on the given CPU.
    pub fn rcu_read_unlock(&mut self, cpu: u32) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS || !self.cpus[c].online {
            return Err(Error::InvalidArgument);
        }
        self.cpus[c].rcu_read_unlock();
        Ok(())
    }

    /// Registers a deferred callback (call_rcu).
    pub fn call_rcu(&mut self, cpu: u32, id: u64, data: u64) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS || !self.cpus[c].online {
            return Err(Error::InvalidArgument);
        }
        // The callback fires after the *next* grace period.
        let gp = self.gp_seq + 1;
        self.cpus[c].call_rcu(id, data, gp)?;
        self.stats.total_callbacks_registered += 1;

        // Start a new grace period if none is in progress.
        if !self.gp_in_progress {
            self.start_grace_period();
        }

        Ok(())
    }

    /// Synchronous RCU wait: blocks until a full grace period
    /// has elapsed. In this implementation, checks if all CPUs
    /// have passed through a quiescent state.
    /// Returns `true` if the grace period completed.
    pub fn synchronize_rcu(&mut self) -> bool {
        if !self.gp_in_progress {
            self.start_grace_period();
        }
        self.try_complete_grace_period()
    }

    /// Reports a quiescent state for a CPU.
    pub fn report_qs(&mut self, cpu: u32) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS || !self.cpus[c].online {
            return Err(Error::InvalidArgument);
        }
        self.cpus[c].report_qs();
        Ok(())
    }

    /// Forces all CPUs to report quiescent states (e.g., at idle).
    pub fn force_qs(&mut self) {
        for c in 0..self.nr_cpus as usize {
            if self.cpus[c].online && !self.cpus[c].in_read_side() {
                self.cpus[c].qs_passed = true;
            }
        }
        self.stats.nr_forced_qs += 1;
    }

    /// Processes callbacks on a CPU. Returns the number invoked.
    pub fn process_callbacks(&mut self, cpu: u32) -> Result<u32> {
        let c = cpu as usize;
        if c >= MAX_CPUS || !self.cpus[c].online {
            return Err(Error::InvalidArgument);
        }
        let count = self.cpus[c].process_callbacks(self.completed);
        self.stats.total_callbacks_invoked += count as u64;
        Ok(count)
    }

    /// Returns per-CPU RCU state.
    pub fn per_cpu(&self, cpu: u32) -> Option<&PerCpuRcu> {
        let c = cpu as usize;
        if c < MAX_CPUS {
            Some(&self.cpus[c])
        } else {
            None
        }
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    fn start_grace_period(&mut self) {
        self.gp_seq += 1;
        self.gp_in_progress = true;
        self.stats.gp_started += 1;
        // Reset all quiescent state flags.
        for c in 0..self.nr_cpus as usize {
            if self.cpus[c].online {
                self.cpus[c].qs_passed = false;
            }
        }
    }

    fn try_complete_grace_period(&mut self) -> bool {
        if !self.gp_in_progress {
            return false;
        }

        // Check if all online CPUs have passed a quiescent state.
        for c in 0..self.nr_cpus as usize {
            if self.cpus[c].online && !self.cpus[c].qs_passed {
                return false;
            }
        }

        // Grace period complete.
        self.completed = self.gp_seq;
        self.gp_in_progress = false;
        self.stats.gp_completed += 1;

        // Process callbacks on all CPUs.
        for c in 0..self.nr_cpus as usize {
            if self.cpus[c].online {
                let count = self.cpus[c].process_callbacks(self.completed);
                self.stats.total_callbacks_invoked += count as u64;
            }
        }

        true
    }
}
