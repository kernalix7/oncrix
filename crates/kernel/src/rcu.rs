// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Read-Copy-Update (RCU) synchronization primitive.
//!
//! RCU allows lock-free read-side access to shared data structures by
//! deferring reclamation of old versions until all pre-existing
//! read-side critical sections have completed. This is modeled after
//! Linux's Tree RCU (`kernel/rcu/`).
//!
//! Key concepts:
//! - **Read-side critical section**: bounded by [`RcuData::rcu_read_lock`]
//!   and [`RcuData::rcu_read_unlock`]. Readers never block.
//! - **Grace period**: a time interval during which every CPU has passed
//!   through at least one quiescent state (context switch outside a
//!   read-side critical section).
//! - **Callbacks**: registered via [`RcuData::call_rcu`], invoked after
//!   the grace period under which they were registered completes.
//!
//! All structures use fixed-size arrays with no heap allocation,
//! suitable for `#![no_std]` kernel environments.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum CPUs supported.
const MAX_CPUS: usize = 8;

/// Maximum pending RCU callbacks.
const MAX_CALLBACKS: usize = 128;

// ======================================================================
// RcuState
// ======================================================================

/// State of an RCU grace period.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RcuState {
    /// No grace period in progress.
    #[default]
    Idle,
    /// A grace period is in progress, waiting for quiescent states.
    GracePeriod,
    /// The grace period has completed; callbacks may be invoked.
    Completed,
}

// ======================================================================
// RcuCallback
// ======================================================================

/// A deferred callback to be invoked after a grace period completes.
#[derive(Debug, Clone, Copy)]
pub struct RcuCallback {
    /// Unique callback identifier.
    pub id: u64,
    /// Identifies the handler function to invoke.
    pub func_id: u64,
    /// Opaque data passed to the handler.
    pub data: u64,
    /// Grace period number this callback is waiting for.
    pub gp_num: u64,
    /// Whether this callback is still pending.
    pub pending: bool,
}

impl RcuCallback {
    /// Create an empty (inactive) callback for array initialisation.
    const fn empty() -> Self {
        Self {
            id: 0,
            func_id: 0,
            data: 0,
            gp_num: 0,
            pending: false,
        }
    }
}

impl Default for RcuCallback {
    fn default() -> Self {
        Self::empty()
    }
}

// ======================================================================
// RcuPerCpu
// ======================================================================

/// Per-CPU RCU tracking state.
#[derive(Debug, Clone, Copy)]
pub struct RcuPerCpu {
    /// CPU identifier.
    pub cpu_id: u32,
    /// Whether this CPU has passed a quiescent state for the current GP.
    pub qs_passed: bool,
    /// Last grace period sequence number acknowledged by this CPU.
    pub gp_seq: u64,
    /// Read-side critical section nesting depth.
    pub nesting: u32,
    /// Whether this per-CPU slot is in use.
    pub in_use: bool,
}

impl RcuPerCpu {
    /// Create an empty per-CPU entry for array initialisation.
    const fn new(cpu_id: u32) -> Self {
        Self {
            cpu_id,
            qs_passed: false,
            gp_seq: 0,
            nesting: 0,
            in_use: false,
        }
    }
}

impl Default for RcuPerCpu {
    fn default() -> Self {
        Self::new(0)
    }
}

// ======================================================================
// RcuGracePeriod
// ======================================================================

/// Tracks the state of a single RCU grace period.
#[derive(Debug, Clone, Copy)]
pub struct RcuGracePeriod {
    /// Grace period sequence number.
    pub gp_num: u64,
    /// Current state of this grace period.
    pub state: RcuState,
    /// Bitmask of CPUs that must report quiescent states.
    pub start_cpu_mask: u64,
    /// Bitmask of CPUs that have reported quiescent states.
    pub completed_mask: u64,
    /// Number of CPUs participating in this grace period.
    pub nr_cpus: u32,
}

impl RcuGracePeriod {
    /// Create an idle grace period for initialisation.
    const fn empty() -> Self {
        Self {
            gp_num: 0,
            state: RcuState::Idle,
            start_cpu_mask: 0,
            completed_mask: 0,
            nr_cpus: 0,
        }
    }

    /// Returns `true` if all participating CPUs have reported
    /// quiescent states.
    pub fn is_complete(&self) -> bool {
        self.state == RcuState::GracePeriod
            && self.nr_cpus > 0
            && self.completed_mask == self.start_cpu_mask
    }
}

impl Default for RcuGracePeriod {
    fn default() -> Self {
        Self::empty()
    }
}

// ======================================================================
// RcuData
// ======================================================================

/// Central RCU state managing per-CPU data, callbacks, and grace periods.
///
/// This is the main entry point for all RCU operations. In a real
/// kernel this would be a global singleton protected by appropriate
/// synchronization; here we model the logic without actual atomic
/// operations.
pub struct RcuData {
    /// Per-CPU RCU state.
    per_cpu: [RcuPerCpu; MAX_CPUS],
    /// Pending RCU callbacks.
    callbacks: [RcuCallback; MAX_CALLBACKS],
    /// Number of active callbacks in the array.
    cb_count: usize,
    /// Current (or most recent) grace period.
    current_gp: RcuGracePeriod,
    /// Next grace period number to assign.
    next_gp_num: u64,
    /// Whether the RCU subsystem is enabled.
    enabled: bool,
    /// Monotonically increasing callback ID counter.
    next_cb_id: u64,
}

impl RcuData {
    /// Create a new RCU subsystem instance.
    pub const fn new() -> Self {
        Self {
            per_cpu: [
                RcuPerCpu::new(0),
                RcuPerCpu::new(1),
                RcuPerCpu::new(2),
                RcuPerCpu::new(3),
                RcuPerCpu::new(4),
                RcuPerCpu::new(5),
                RcuPerCpu::new(6),
                RcuPerCpu::new(7),
            ],
            callbacks: [RcuCallback::empty(); MAX_CALLBACKS],
            cb_count: 0,
            current_gp: RcuGracePeriod::empty(),
            next_gp_num: 1,
            enabled: false,
            next_cb_id: 1,
        }
    }

    /// Enter an RCU read-side critical section on the given CPU.
    ///
    /// Increments the nesting counter. While nesting > 0, the CPU
    /// cannot report a quiescent state.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of range.
    pub fn rcu_read_lock(&mut self, cpu_id: u32) -> Result<()> {
        let cpu = self.get_cpu_mut(cpu_id)?;
        cpu.nesting = cpu.nesting.saturating_add(1);
        Ok(())
    }

    /// Exit an RCU read-side critical section on the given CPU.
    ///
    /// Decrements the nesting counter. When it reaches zero, the CPU
    /// may report a quiescent state on the next context switch.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of range.
    /// Returns [`Error::InvalidState`] if nesting is already zero.
    pub fn rcu_read_unlock(&mut self, cpu_id: u32) -> Result<()> {
        let cpu = self.get_cpu_mut(cpu_id)?;
        if cpu.nesting == 0 {
            return Err(Error::InvalidArgument);
        }
        cpu.nesting -= 1;
        Ok(())
    }

    /// Register a callback to be invoked after the current grace
    /// period completes.
    ///
    /// If no grace period is active, the callback is associated with
    /// the next one that will be started. Returns the callback ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the callback table is full.
    pub fn call_rcu(&mut self, func_id: u64, data: u64) -> Result<u64> {
        if self.cb_count >= MAX_CALLBACKS {
            return Err(Error::OutOfMemory);
        }

        let gp_num = if self.current_gp.state == RcuState::GracePeriod {
            self.current_gp.gp_num
        } else {
            self.next_gp_num
        };

        let id = self.next_cb_id;
        self.next_cb_id = self.next_cb_id.wrapping_add(1);

        // Find the first unused slot.
        let slot = self
            .callbacks
            .iter()
            .position(|cb| !cb.pending)
            .ok_or(Error::OutOfMemory)?;

        self.callbacks[slot] = RcuCallback {
            id,
            func_id,
            data,
            gp_num,
            pending: true,
        };
        self.cb_count = self.cb_count.saturating_add(1);

        Ok(id)
    }

    /// Start a grace period and conceptually wait for it to complete.
    ///
    /// This is the synchronous RCU barrier: it starts a new grace
    /// period (if one is not already in progress) and returns. In a
    /// real kernel the caller would block until all CPUs pass through
    /// a quiescent state; here we simply ensure a grace period is
    /// initiated.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if a grace period is already in
    /// progress.
    pub fn synchronize_rcu(&mut self) -> Result<()> {
        if self.current_gp.state == RcuState::GracePeriod {
            return Err(Error::Busy);
        }
        self.start_grace_period()
    }

    /// Note a context switch on the given CPU — this is a quiescent
    /// state if the CPU is not inside a read-side critical section.
    ///
    /// If all CPUs have passed through a quiescent state, the grace
    /// period advances to [`RcuState::Completed`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of range.
    pub fn rcu_note_context_switch(&mut self, cpu_id: u32) -> Result<()> {
        if cpu_id as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        // Only record quiescent state if not in a read-side section.
        if self.per_cpu[cpu_id as usize].nesting > 0 {
            return Ok(());
        }

        self.per_cpu[cpu_id as usize].qs_passed = true;

        // If a grace period is active, advance it.
        if self.current_gp.state == RcuState::GracePeriod {
            let _ = self.advance_grace_period(cpu_id)?;
        }

        Ok(())
    }

    /// Process callbacks whose grace period has completed.
    ///
    /// Returns the number of callbacks processed (removed from the
    /// pending list).
    pub fn rcu_check_callbacks(&mut self) -> Result<u32> {
        if self.current_gp.state != RcuState::Completed {
            return Ok(0);
        }

        let completed_gp = self.current_gp.gp_num;
        let mut processed: u32 = 0;

        for cb in &mut self.callbacks {
            if cb.pending && cb.gp_num <= completed_gp {
                cb.pending = false;
                processed = processed.saturating_add(1);
            }
        }

        self.cb_count = self.cb_count.saturating_sub(processed as usize);

        // Transition back to idle so a new grace period can start.
        self.current_gp.state = RcuState::Idle;

        Ok(processed)
    }

    /// Start a new grace period.
    ///
    /// Initialises the grace period structure with the set of CPUs
    /// that are currently in use (have `in_use` set) and sets the
    /// state to [`RcuState::GracePeriod`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if a grace period is already in
    /// progress.
    pub fn start_grace_period(&mut self) -> Result<()> {
        if self.current_gp.state == RcuState::GracePeriod {
            return Err(Error::Busy);
        }

        let gp_num = self.next_gp_num;
        self.next_gp_num = self.next_gp_num.wrapping_add(1);

        let mut cpu_mask: u64 = 0;
        let mut nr_cpus: u32 = 0;

        for cpu in &mut self.per_cpu {
            if cpu.in_use {
                cpu_mask |= 1u64 << cpu.cpu_id;
                nr_cpus = nr_cpus.saturating_add(1);
                cpu.qs_passed = false;
                cpu.gp_seq = gp_num;
            }
        }

        // If no CPUs are active, complete immediately.
        if nr_cpus == 0 {
            self.current_gp = RcuGracePeriod {
                gp_num,
                state: RcuState::Completed,
                start_cpu_mask: 0,
                completed_mask: 0,
                nr_cpus: 0,
            };
            return Ok(());
        }

        self.current_gp = RcuGracePeriod {
            gp_num,
            state: RcuState::GracePeriod,
            start_cpu_mask: cpu_mask,
            completed_mask: 0,
            nr_cpus,
        };

        Ok(())
    }

    /// Advance the current grace period by recording that `cpu_id`
    /// has passed a quiescent state.
    ///
    /// Returns `true` if this was the final CPU and the grace period
    /// is now complete.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of range.
    /// Returns [`Error::InvalidArgument`] if no grace period is
    /// active.
    pub fn advance_grace_period(&mut self, cpu_id: u32) -> Result<bool> {
        if cpu_id as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if self.current_gp.state != RcuState::GracePeriod {
            return Err(Error::InvalidArgument);
        }

        let cpu_bit = 1u64 << cpu_id;

        // Only count this CPU if it is part of the grace period and
        // has passed a quiescent state.
        if self.per_cpu[cpu_id as usize].qs_passed
            && (self.current_gp.start_cpu_mask & cpu_bit) != 0
        {
            self.current_gp.completed_mask |= cpu_bit;
        }

        if self.current_gp.is_complete() {
            self.current_gp.state = RcuState::Completed;
            return Ok(true);
        }

        Ok(false)
    }

    /// Return the number of pending callbacks.
    pub fn pending_callbacks(&self) -> usize {
        self.cb_count
    }

    /// Return the total number of active callbacks.
    pub fn len(&self) -> usize {
        self.cb_count
    }

    /// Return `true` if there are no pending callbacks.
    pub fn is_empty(&self) -> bool {
        self.cb_count == 0
    }

    /// Return `true` if the given CPU is inside a read-side critical
    /// section (nesting > 0).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of range.
    pub fn is_in_read_side(&self, cpu_id: u32) -> Result<bool> {
        let cpu = self.get_cpu(cpu_id)?;
        Ok(cpu.nesting > 0)
    }

    /// Return a shared reference to the per-CPU entry, with bounds
    /// checking.
    fn get_cpu(&self, cpu_id: u32) -> Result<&RcuPerCpu> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.per_cpu[idx])
    }

    /// Return a mutable reference to the per-CPU entry, with bounds
    /// checking.
    fn get_cpu_mut(&mut self, cpu_id: u32) -> Result<&mut RcuPerCpu> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.per_cpu[idx])
    }
}

impl Default for RcuData {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for RcuData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RcuData")
            .field("cb_count", &self.cb_count)
            .field("current_gp", &self.current_gp)
            .field("next_gp_num", &self.next_gp_num)
            .field("enabled", &self.enabled)
            .finish()
    }
}
