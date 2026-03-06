// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RCU no-callback (NOCB) offloading.
//!
//! Offloads RCU callback invocation from normal CPUs to dedicated
//! `rcuog` and `rcuop` kthreads. This prevents callback processing
//! from interfering with latency-sensitive workloads on isolated or
//! NOHZ_FULL CPUs.
//!
//! # Architecture
//!
//! ```text
//! CPU N (nocb)                     rcuog kthread
//! ┌──────────────┐                ┌──────────────┐
//! │ call_rcu()   │───offload────>│ GP wait       │
//! │ (no local CB)│                │ CB batch      │
//! └──────────────┘                └──────┬───────┘
//!                                        │
//!                                        v
//!                                 rcuop kthread
//!                                 ┌──────────────┐
//!                                 │ Invoke CBs    │
//!                                 └──────────────┘
//! ```
//!
//! - **rcuog** (grace-period offload): waits for grace periods on
//!   behalf of nocb CPUs, then hands batches to rcuop.
//! - **rcuop** (callback offload): invokes mature callbacks.
//! - **nocb state**: per-CPU state tracking offloaded callbacks,
//!   wake flags, and kthread references.
//!
//! # Callback Flow
//!
//! 1. CPU calls `call_rcu()` → callback queued to nocb segment
//! 2. rcuog kthread wakes, waits for GP completion
//! 3. After GP, callbacks moved to done list
//! 4. rcuop kthread wakes, invokes done callbacks
//! 5. After invocation, callbacks freed
//!
//! Reference: Linux `kernel/rcu/tree_nocb.h`,
//! `kernel/rcu/tree_plugin.h`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum CPUs supporting NOCB mode.
const MAX_CPUS: usize = 64;

/// Maximum callbacks per CPU pending offload.
const MAX_CALLBACKS_PER_CPU: usize = 256;

/// Maximum callbacks in the done queue per kthread.
const MAX_DONE_CALLBACKS: usize = 512;

/// Maximum NOCB kthread groups.
const MAX_KTHREAD_GROUPS: usize = 16;

/// Callback batch size for rcuop processing.
const CALLBACK_BATCH_SIZE: usize = 32;

/// Wake retry limit before forcing a wake.
const WAKE_RETRY_LIMIT: u32 = 4;

// ── Callback State ─────────────────────────────────────────────────

/// State of an RCU callback in the NOCB pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NocbCallbackState {
    /// Callback is in the pending segment (not yet GP-waited).
    #[default]
    Pending,
    /// Callback is waiting for a grace period to complete.
    WaitingGp,
    /// Grace period completed; callback is ready for invocation.
    Ready,
    /// Callback has been invoked and can be freed.
    Done,
}

// ── NOCB Callback ──────────────────────────────────────────────────

/// A single RCU callback offloaded to NOCB processing.
#[derive(Debug, Clone, Copy)]
pub struct NocbCallback {
    /// Unique callback ID.
    pub id: u64,
    /// Handler function identifier.
    pub func_id: u64,
    /// Opaque data for the handler.
    pub data: u64,
    /// Grace period number this callback is waiting for.
    pub gp_num: u64,
    /// Current state in the NOCB pipeline.
    pub state: NocbCallbackState,
    /// CPU that originally queued this callback.
    pub source_cpu: u32,
    /// Timestamp (ticks) when the callback was queued.
    pub queue_time: u64,
}

impl NocbCallback {
    /// Create an empty callback for array initialization.
    const fn empty() -> Self {
        Self {
            id: 0,
            func_id: 0,
            data: 0,
            gp_num: 0,
            state: NocbCallbackState::Pending,
            source_cpu: 0,
            queue_time: 0,
        }
    }
}

// ── Per-CPU NOCB State ─────────────────────────────────────────────

/// NOCB operational mode for a CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NocbMode {
    /// CPU processes callbacks locally (not offloaded).
    #[default]
    Normal,
    /// CPU offloads callbacks to NOCB kthreads.
    Offloaded,
    /// CPU is transitioning to offloaded mode.
    Transitioning,
}

/// Wake state flags for NOCB kthread coordination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NocbWakeState {
    /// No wake pending.
    #[default]
    Idle,
    /// Wake is pending (callbacks queued).
    WakePending,
    /// Kthread has been woken and is processing.
    Active,
    /// Kthread needs to be re-woken (new callbacks arrived).
    Rewake,
}

/// Per-CPU NOCB state.
///
/// Tracks the offload state, pending callbacks, and kthread
/// coordination for a single CPU.
pub struct NocbCpuState {
    /// CPU index.
    cpu_id: u32,
    /// NOCB operational mode.
    mode: NocbMode,
    /// Pending callbacks (not yet GP-waited).
    pending: [NocbCallback; MAX_CALLBACKS_PER_CPU],
    /// Number of pending callbacks.
    pending_count: usize,
    /// Index of the kthread group handling this CPU.
    kthread_group: u32,
    /// Current wake state.
    wake_state: NocbWakeState,
    /// Number of wake attempts without response.
    wake_retries: u32,
    /// Next callback ID to assign.
    next_cb_id: u64,
    /// Total callbacks offloaded from this CPU.
    total_offloaded: u64,
    /// Total callbacks invoked for this CPU.
    total_invoked: u64,
    /// Whether this CPU is in a quiescent state.
    quiescent: bool,
    /// Whether this CPU slot is active.
    active: bool,
}

impl NocbCpuState {
    /// Create an empty (inactive) CPU state.
    const fn empty() -> Self {
        Self {
            cpu_id: 0,
            mode: NocbMode::Normal,
            pending: [NocbCallback::empty(); MAX_CALLBACKS_PER_CPU],
            pending_count: 0,
            kthread_group: 0,
            wake_state: NocbWakeState::Idle,
            wake_retries: 0,
            next_cb_id: 1,
            total_offloaded: 0,
            total_invoked: 0,
            quiescent: false,
            active: false,
        }
    }
}

// ── NOCB Kthread Group ─────────────────────────────────────────────

/// Kthread state for a NOCB offload group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KthreadState {
    /// Kthread is not yet created.
    #[default]
    NotCreated,
    /// Kthread is sleeping (waiting for work).
    Sleeping,
    /// Kthread is actively processing.
    Running,
    /// Kthread is shutting down.
    ShuttingDown,
}

/// A NOCB kthread group manages callback offloading for a set of
/// CPUs.
///
/// Each group contains one `rcuog` kthread (GP waiting) and one
/// `rcuop` kthread (callback invocation).
pub struct NocbKthreadGroup {
    /// Group index.
    group_id: u32,
    /// CPUs assigned to this group (bitmask, up to 64 CPUs).
    cpu_mask: u64,
    /// Number of CPUs in this group.
    cpu_count: u32,
    /// rcuog kthread state.
    gp_kthread_state: KthreadState,
    /// rcuop kthread state.
    cb_kthread_state: KthreadState,
    /// Done queue: callbacks ready for invocation.
    done_queue: [NocbCallback; MAX_DONE_CALLBACKS],
    /// Number of callbacks in the done queue.
    done_count: usize,
    /// Current grace period number being waited on.
    current_gp: u64,
    /// Last completed grace period number.
    completed_gp: u64,
    /// Total callbacks processed by this group.
    total_processed: u64,
    /// Total GP waits performed.
    total_gp_waits: u64,
    /// Whether this group is active.
    active: bool,
}

impl NocbKthreadGroup {
    /// Create an empty (inactive) kthread group.
    const fn empty() -> Self {
        Self {
            group_id: 0,
            cpu_mask: 0,
            cpu_count: 0,
            gp_kthread_state: KthreadState::NotCreated,
            cb_kthread_state: KthreadState::NotCreated,
            done_queue: [NocbCallback::empty(); MAX_DONE_CALLBACKS],
            done_count: 0,
            current_gp: 0,
            completed_gp: 0,
            total_processed: 0,
            total_gp_waits: 0,
            active: false,
        }
    }
}

// ── Statistics ─────────────────────────────────────────────────────

/// Aggregate NOCB subsystem statistics.
#[derive(Debug, Clone, Copy)]
pub struct NocbStats {
    /// Total CPUs in NOCB mode.
    pub nocb_cpus: u32,
    /// Total active kthread groups.
    pub active_groups: u32,
    /// Total callbacks offloaded.
    pub total_offloaded: u64,
    /// Total callbacks invoked.
    pub total_invoked: u64,
    /// Total grace periods completed.
    pub total_gp_completed: u64,
    /// Total wake operations.
    pub total_wakes: u64,
    /// Total forced wakes (retry limit exceeded).
    pub total_forced_wakes: u64,
}

impl NocbStats {
    /// Create zeroed statistics.
    const fn new() -> Self {
        Self {
            nocb_cpus: 0,
            active_groups: 0,
            total_offloaded: 0,
            total_invoked: 0,
            total_gp_completed: 0,
            total_wakes: 0,
            total_forced_wakes: 0,
        }
    }
}

// ── NOCB Manager ───────────────────────────────────────────────────

/// System-wide RCU NOCB offload manager.
///
/// Coordinates callback offloading across all CPUs and kthread
/// groups. Provides the API for configuring NOCB mode, queuing
/// callbacks, and driving the offload pipeline.
pub struct NocbManager {
    /// Per-CPU NOCB state.
    cpus: [NocbCpuState; MAX_CPUS],
    /// Kthread groups.
    groups: [NocbKthreadGroup; MAX_KTHREAD_GROUPS],
    /// Number of active kthread groups.
    group_count: usize,
    /// Global NOCB statistics.
    stats: NocbStats,
    /// Global grace period counter.
    global_gp: u64,
}

impl NocbManager {
    /// Create a new NOCB manager with all CPUs in normal mode.
    pub const fn new() -> Self {
        Self {
            cpus: [const { NocbCpuState::empty() }; MAX_CPUS],
            groups: [
                NocbKthreadGroup::empty(),
                NocbKthreadGroup::empty(),
                NocbKthreadGroup::empty(),
                NocbKthreadGroup::empty(),
                NocbKthreadGroup::empty(),
                NocbKthreadGroup::empty(),
                NocbKthreadGroup::empty(),
                NocbKthreadGroup::empty(),
                NocbKthreadGroup::empty(),
                NocbKthreadGroup::empty(),
                NocbKthreadGroup::empty(),
                NocbKthreadGroup::empty(),
                NocbKthreadGroup::empty(),
                NocbKthreadGroup::empty(),
                NocbKthreadGroup::empty(),
                NocbKthreadGroup::empty(),
            ],
            group_count: 0,
            stats: NocbStats::new(),
            global_gp: 1,
        }
    }

    /// Enable NOCB mode for a CPU.
    ///
    /// The CPU must not already be in NOCB mode. A kthread group
    /// must be created first (or the CPU is assigned to an existing
    /// group).
    pub fn enable_nocb(&mut self, cpu_id: u32, group_id: u32) -> Result<()> {
        let cpu_idx = cpu_id as usize;
        if cpu_idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let grp_idx = group_id as usize;
        if grp_idx >= MAX_KTHREAD_GROUPS || !self.groups[grp_idx].active {
            return Err(Error::NotFound);
        }
        if self.cpus[cpu_idx].active && self.cpus[cpu_idx].mode == NocbMode::Offloaded {
            return Err(Error::AlreadyExists);
        }

        self.cpus[cpu_idx].cpu_id = cpu_id;
        self.cpus[cpu_idx].mode = NocbMode::Offloaded;
        self.cpus[cpu_idx].kthread_group = group_id;
        self.cpus[cpu_idx].active = true;

        // Add CPU to group mask
        self.groups[grp_idx].cpu_mask |= 1u64 << (cpu_id as u64);
        self.groups[grp_idx].cpu_count += 1;

        self.stats.nocb_cpus += 1;
        Ok(())
    }

    /// Disable NOCB mode for a CPU.
    ///
    /// Pending callbacks are drained before switching back to normal
    /// mode.
    pub fn disable_nocb(&mut self, cpu_id: u32) -> Result<()> {
        let cpu_idx = cpu_id as usize;
        if cpu_idx >= MAX_CPUS || !self.cpus[cpu_idx].active {
            return Err(Error::NotFound);
        }
        if self.cpus[cpu_idx].mode != NocbMode::Offloaded {
            return Err(Error::InvalidArgument);
        }
        if self.cpus[cpu_idx].pending_count > 0 {
            return Err(Error::Busy);
        }

        let grp_idx = self.cpus[cpu_idx].kthread_group as usize;
        self.groups[grp_idx].cpu_mask &= !(1u64 << (cpu_id as u64));
        self.groups[grp_idx].cpu_count = self.groups[grp_idx].cpu_count.saturating_sub(1);

        self.cpus[cpu_idx].mode = NocbMode::Normal;
        self.stats.nocb_cpus = self.stats.nocb_cpus.saturating_sub(1);
        Ok(())
    }

    /// Create a new NOCB kthread group.
    ///
    /// Returns the group index. The kthreads start in
    /// [`KthreadState::Sleeping`].
    pub fn create_group(&mut self) -> Result<u32> {
        if self.group_count >= MAX_KTHREAD_GROUPS {
            return Err(Error::OutOfMemory);
        }
        let slot = self
            .groups
            .iter()
            .position(|g| !g.active)
            .ok_or(Error::OutOfMemory)?;
        let grp = &mut self.groups[slot];
        grp.group_id = slot as u32;
        grp.cpu_mask = 0;
        grp.cpu_count = 0;
        grp.gp_kthread_state = KthreadState::Sleeping;
        grp.cb_kthread_state = KthreadState::Sleeping;
        grp.done_count = 0;
        grp.current_gp = self.global_gp;
        grp.completed_gp = 0;
        grp.total_processed = 0;
        grp.total_gp_waits = 0;
        grp.active = true;
        self.group_count += 1;
        self.stats.active_groups = self.group_count as u32;
        Ok(slot as u32)
    }

    /// Destroy a NOCB kthread group.
    ///
    /// The group must have no CPUs assigned.
    pub fn destroy_group(&mut self, group_id: u32) -> Result<()> {
        let idx = group_id as usize;
        if idx >= MAX_KTHREAD_GROUPS || !self.groups[idx].active {
            return Err(Error::NotFound);
        }
        if self.groups[idx].cpu_count > 0 {
            return Err(Error::Busy);
        }
        self.groups[idx] = NocbKthreadGroup::empty();
        self.group_count = self.group_count.saturating_sub(1);
        self.stats.active_groups = self.group_count as u32;
        Ok(())
    }

    /// Queue an RCU callback for NOCB offloading.
    ///
    /// If the CPU is in NOCB mode, the callback is queued to the
    /// CPU's pending list and the kthread group is woken.
    pub fn call_rcu(&mut self, cpu_id: u32, func_id: u64, data: u64, now: u64) -> Result<u64> {
        let cpu_idx = cpu_id as usize;
        if cpu_idx >= MAX_CPUS || !self.cpus[cpu_idx].active {
            return Err(Error::NotFound);
        }
        if self.cpus[cpu_idx].mode != NocbMode::Offloaded {
            return Err(Error::InvalidArgument);
        }
        if self.cpus[cpu_idx].pending_count >= MAX_CALLBACKS_PER_CPU {
            return Err(Error::OutOfMemory);
        }

        let cb_id = self.cpus[cpu_idx].next_cb_id;
        self.cpus[cpu_idx].next_cb_id += 1;

        let pc = self.cpus[cpu_idx].pending_count;
        self.cpus[cpu_idx].pending[pc] = NocbCallback {
            id: cb_id,
            func_id,
            data,
            gp_num: self.global_gp,
            state: NocbCallbackState::Pending,
            source_cpu: cpu_id,
            queue_time: now,
        };
        self.cpus[cpu_idx].pending_count += 1;
        self.cpus[cpu_idx].total_offloaded += 1;

        // Signal wake to the kthread group
        let group = self.cpus[cpu_idx].kthread_group;
        self.wake_group(group);
        self.stats.total_offloaded += 1;

        Ok(cb_id)
    }

    /// Advance the global grace period.
    ///
    /// Called when a grace period completes. Transitions all callbacks
    /// waiting for this GP to the Ready state and moves them to the
    /// done queue of their kthread group.
    pub fn advance_gp(&mut self) -> Result<u64> {
        let completed_gp = self.global_gp;
        self.global_gp += 1;

        // Process each CPU's pending callbacks
        for cpu_idx in 0..MAX_CPUS {
            if !self.cpus[cpu_idx].active || self.cpus[cpu_idx].mode != NocbMode::Offloaded {
                continue;
            }

            let grp_idx = self.cpus[cpu_idx].kthread_group as usize;
            if grp_idx >= MAX_KTHREAD_GROUPS || !self.groups[grp_idx].active {
                continue;
            }

            // Move matured callbacks to done queue.
            // Collect indices first, then process.
            let mut move_count = 0usize;
            let mut move_indices = [0usize; MAX_CALLBACKS_PER_CPU];
            for ci in 0..self.cpus[cpu_idx].pending_count {
                let cb = &self.cpus[cpu_idx].pending[ci];
                if cb.gp_num <= completed_gp && cb.state == NocbCallbackState::Pending {
                    if move_count < MAX_CALLBACKS_PER_CPU {
                        move_indices[move_count] = ci;
                        move_count += 1;
                    }
                }
            }

            // Move callbacks to done queue
            for mi in 0..move_count {
                let ci = move_indices[mi];
                let grp = &mut self.groups[grp_idx];
                if grp.done_count < MAX_DONE_CALLBACKS {
                    let mut cb = self.cpus[cpu_idx].pending[ci];
                    cb.state = NocbCallbackState::Ready;
                    grp.done_queue[grp.done_count] = cb;
                    grp.done_count += 1;
                }
                self.cpus[cpu_idx].pending[ci].state = NocbCallbackState::Done;
            }

            // Compact the pending list
            self.compact_pending(cpu_idx);

            // Update group GP state
            self.groups[grp_idx].completed_gp = completed_gp;
            self.groups[grp_idx].total_gp_waits += 1;
        }

        self.stats.total_gp_completed += 1;
        Ok(self.global_gp)
    }

    /// Process done callbacks in a kthread group.
    ///
    /// Simulates the `rcuop` kthread invoking callbacks from the
    /// done queue. Processes up to `CALLBACK_BATCH_SIZE` callbacks.
    ///
    /// Returns the number of callbacks processed.
    pub fn process_callbacks(&mut self, group_id: u32) -> Result<usize> {
        let idx = group_id as usize;
        if idx >= MAX_KTHREAD_GROUPS || !self.groups[idx].active {
            return Err(Error::NotFound);
        }

        let grp = &mut self.groups[idx];
        grp.cb_kthread_state = KthreadState::Running;

        let batch = grp.done_count.min(CALLBACK_BATCH_SIZE);
        let mut processed = 0usize;

        for _ in 0..batch {
            if grp.done_count == 0 {
                break;
            }
            // "Invoke" the callback (mark as Done)
            grp.done_queue[0].state = NocbCallbackState::Done;
            let source_cpu = grp.done_queue[0].source_cpu as usize;

            // Shift the done queue
            for i in 0..grp.done_count.saturating_sub(1) {
                grp.done_queue[i] = grp.done_queue[i + 1];
            }
            if grp.done_count > 0 {
                grp.done_queue[grp.done_count - 1] = NocbCallback::empty();
                grp.done_count -= 1;
            }
            processed += 1;
            grp.total_processed += 1;

            // Update per-CPU stats
            if source_cpu < MAX_CPUS && self.cpus[source_cpu].active {
                self.cpus[source_cpu].total_invoked += 1;
            }
        }

        self.stats.total_invoked += processed as u64;

        // Return to sleeping if no more work
        if grp.done_count == 0 {
            grp.cb_kthread_state = KthreadState::Sleeping;
        }

        Ok(processed)
    }

    /// Query the NOCB mode for a CPU.
    pub fn get_cpu_mode(&self, cpu_id: u32) -> Result<NocbMode> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS || !self.cpus[idx].active {
            return Err(Error::NotFound);
        }
        Ok(self.cpus[idx].mode)
    }

    /// Query the number of pending callbacks for a CPU.
    pub fn pending_count(&self, cpu_id: u32) -> Result<usize> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS || !self.cpus[idx].active {
            return Err(Error::NotFound);
        }
        Ok(self.cpus[idx].pending_count)
    }

    /// Query the done queue length for a kthread group.
    pub fn done_count(&self, group_id: u32) -> Result<usize> {
        let idx = group_id as usize;
        if idx >= MAX_KTHREAD_GROUPS || !self.groups[idx].active {
            return Err(Error::NotFound);
        }
        Ok(self.groups[idx].done_count)
    }

    /// Get the current global grace period number.
    pub fn current_gp(&self) -> u64 {
        self.global_gp
    }

    /// Get aggregate NOCB statistics.
    pub fn statistics(&self) -> &NocbStats {
        &self.stats
    }

    /// Report a quiescent state for a CPU.
    ///
    /// In NOCB mode, quiescent states are tracked to determine
    /// when grace periods can complete.
    pub fn note_quiescent(&mut self, cpu_id: u32) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS || !self.cpus[idx].active {
            return Err(Error::NotFound);
        }
        self.cpus[idx].quiescent = true;
        Ok(())
    }

    /// Check if all NOCB CPUs have reported quiescent states.
    pub fn all_quiescent(&self) -> bool {
        for cpu in &self.cpus {
            if cpu.active && cpu.mode == NocbMode::Offloaded && !cpu.quiescent {
                return false;
            }
        }
        true
    }

    /// Reset quiescent state tracking for a new grace period.
    pub fn reset_quiescent(&mut self) {
        for cpu in &mut self.cpus {
            if cpu.active && cpu.mode == NocbMode::Offloaded {
                cpu.quiescent = false;
            }
        }
    }

    // ── Internal helpers ───────────────────────────────────────────

    /// Wake a kthread group to process callbacks.
    fn wake_group(&mut self, group_id: u32) {
        let idx = group_id as usize;
        if idx >= MAX_KTHREAD_GROUPS || !self.groups[idx].active {
            return;
        }
        self.groups[idx].gp_kthread_state = KthreadState::Running;
        self.stats.total_wakes += 1;
    }

    /// Compact the pending callback list for a CPU by removing
    /// callbacks in the Done state.
    fn compact_pending(&mut self, cpu_idx: usize) {
        let cpu = &mut self.cpus[cpu_idx];
        let mut write = 0;
        for read in 0..cpu.pending_count {
            if cpu.pending[read].state != NocbCallbackState::Done {
                if write != read {
                    cpu.pending[write] = cpu.pending[read];
                }
                write += 1;
            }
        }
        for i in write..cpu.pending_count {
            cpu.pending[i] = NocbCallback::empty();
        }
        cpu.pending_count = write;
    }
}
