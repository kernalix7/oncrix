// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Stop-machine facility for serialised critical sections.
//!
//! Provides a mechanism to execute a function on a single CPU
//! while all other CPUs are parked in a known-safe busy loop.
//! This is the microkernel equivalent of Linux's `stop_machine()`.
//!
//! # Use Cases
//!
//! - CPU hotplug: safely migrate tasks before offlining a CPU.
//! - Module loading: patch kernel text while no CPU can execute
//!   the patched region.
//! - Live patching: swap function pointers atomically.
//! - Critical firmware calls: execute SMI handlers with all
//!   cores quiesced.
//!
//! # Architecture
//!
//! ```text
//! stop_machine_run(work)
//!   │
//!   ├──► StopMachineState::Idle
//!   │       └── validate work, choose executor CPU
//!   │
//!   ├──► StopMachineState::Requesting
//!   │       └── send IPI to all other CPUs
//!   │
//!   ├──► StopMachineState::AllStopped
//!   │       └── all CPUs acked; executor runs work fn
//!   │
//!   └──► StopMachineState::Done
//!           └── release all CPUs; return result
//! ```
//!
//! # Safety Contract
//!
//! While the machine is stopped, no scheduling, no interrupts
//! (except NMI), and no timer ticks occur on non-executor CPUs.
//! The executor function must complete quickly to avoid watchdog
//! timeouts and NMI storms.
//!
//! Reference: Linux `kernel/stop_machine.c`,
//! `include/linux/stop_machine.h`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────

/// Maximum number of CPUs the stop-machine can manage.
const MAX_CPUS: usize = 64;

/// Maximum number of queued stop-machine work items.
const MAX_WORK_QUEUE: usize = 16;

/// Maximum timeout waiting for all CPUs to stop (in ticks).
const DEFAULT_TIMEOUT_TICKS: u64 = 10_000;

/// Sentinel value indicating no CPU.
const CPU_NONE: u32 = u32::MAX;

// ── StopMachineState ───────────────────────────────────────────

/// Top-level state of the stop-machine facility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StopMachineState {
    /// The facility is idle and ready to accept work.
    #[default]
    Idle,
    /// A stop request has been issued; waiting for CPUs to
    /// acknowledge.
    Requesting,
    /// All CPUs have stopped; the executor is running.
    AllStopped,
    /// The work function has completed; CPUs are being released.
    Done,
    /// An error occurred (e.g., timeout waiting for CPUs).
    Failed,
}

// ── CpuStopState ───────────────────────────────────────────────

/// Per-CPU state during a stop-machine operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CpuStopState {
    /// CPU has not yet received the stop request.
    #[default]
    Running,
    /// CPU has received the stop IPI and is entering its
    /// busy-wait loop.
    Stopping,
    /// CPU is parked in the busy-wait loop.
    Stopped,
    /// CPU has been released and is resuming normal operation.
    Resumed,
}

// ── CpuStop ────────────────────────────────────────────────────

/// Per-CPU tracking structure for stop-machine operations.
#[derive(Debug, Clone, Copy)]
pub struct CpuStop {
    /// Logical CPU identifier.
    pub cpu_id: u32,
    /// Current stop state for this CPU.
    pub state: CpuStopState,
    /// Whether this CPU is online and participating.
    pub online: bool,
    /// Timestamp (tick count) when the stop request was
    /// acknowledged.
    pub ack_tick: u64,
    /// Whether this CPU slot is in use.
    pub active: bool,
}

impl Default for CpuStop {
    fn default() -> Self {
        Self::empty()
    }
}

impl CpuStop {
    /// Create an empty (unused) CPU stop entry.
    pub const fn empty() -> Self {
        Self {
            cpu_id: CPU_NONE,
            state: CpuStopState::Running,
            online: false,
            ack_tick: 0,
            active: false,
        }
    }
}

// ── StopWork ───────────────────────────────────────────────────

/// A work item to be executed under stop-machine protection.
#[derive(Debug, Clone, Copy)]
pub struct StopWork {
    /// Unique work item identifier.
    pub id: u32,
    /// Callback function identifier (resolved by the caller).
    pub callback_id: u32,
    /// Opaque argument passed to the callback.
    pub arg: u64,
    /// CPU on which the work should execute (CPU_NONE = any).
    pub target_cpu: u32,
    /// Whether this work slot is in use.
    pub active: bool,
    /// Whether the work has been executed.
    pub completed: bool,
    /// Result code from the callback (0 = success).
    pub result_code: i32,
}

impl Default for StopWork {
    fn default() -> Self {
        Self::empty()
    }
}

impl StopWork {
    /// Create an empty work item.
    pub const fn empty() -> Self {
        Self {
            id: 0,
            callback_id: 0,
            arg: 0,
            target_cpu: CPU_NONE,
            active: false,
            completed: false,
            result_code: 0,
        }
    }
}

// ── StopResult ─────────────────────────────────────────────────

/// Result of a stop-machine operation.
#[derive(Debug, Clone, Copy)]
pub struct StopResult {
    /// Work item ID that was executed.
    pub work_id: u32,
    /// CPU that executed the work.
    pub executor_cpu: u32,
    /// Number of CPUs that were stopped.
    pub cpus_stopped: u32,
    /// Duration of the stop (in ticks).
    pub stop_duration_ticks: u64,
    /// Whether the operation succeeded.
    pub success: bool,
    /// Result code from the work callback.
    pub result_code: i32,
}

impl Default for StopResult {
    fn default() -> Self {
        Self {
            work_id: 0,
            executor_cpu: CPU_NONE,
            cpus_stopped: 0,
            stop_duration_ticks: 0,
            success: false,
            result_code: 0,
        }
    }
}

// ── StopMachineStats ───────────────────────────────────────────

/// Cumulative statistics for the stop-machine facility.
#[derive(Debug, Clone, Copy, Default)]
pub struct StopMachineStats {
    /// Total number of stop-machine operations.
    pub total_operations: u64,
    /// Number of successful operations.
    pub successful: u64,
    /// Number of failed operations.
    pub failed: u64,
    /// Number of timeout failures.
    pub timeouts: u64,
    /// Total ticks spent in stopped state across all
    /// operations.
    pub total_stopped_ticks: u64,
    /// Maximum stop duration observed (in ticks).
    pub max_stop_ticks: u64,
}

// ── StopMachine ────────────────────────────────────────────────

/// The stop-machine facility.
///
/// Coordinates quiescing all CPUs, executing critical code on
/// a single executor, and then resuming all CPUs. At most one
/// stop-machine operation can be in progress at a time.
pub struct StopMachine {
    /// Current state of the facility.
    state: StopMachineState,
    /// Per-CPU stop tracking.
    cpus: [CpuStop; MAX_CPUS],
    /// Number of online CPUs.
    online_count: u32,
    /// Queued work items.
    work_queue: [StopWork; MAX_WORK_QUEUE],
    /// Number of pending work items.
    pending_count: usize,
    /// Next work item ID to assign.
    next_work_id: u32,
    /// CPU chosen to execute the current work.
    executor_cpu: u32,
    /// Tick counter when the current operation started.
    start_tick: u64,
    /// Current tick counter (updated by the caller).
    current_tick: u64,
    /// Timeout in ticks for waiting on CPU acknowledgements.
    timeout_ticks: u64,
    /// Cumulative statistics.
    stats: StopMachineStats,
}

impl Default for StopMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl StopMachine {
    /// Create a new stop-machine facility.
    pub const fn new() -> Self {
        Self {
            state: StopMachineState::Idle,
            cpus: [CpuStop::empty(); MAX_CPUS],
            online_count: 0,
            work_queue: [StopWork::empty(); MAX_WORK_QUEUE],
            pending_count: 0,
            next_work_id: 1,
            executor_cpu: CPU_NONE,
            start_tick: 0,
            current_tick: 0,
            timeout_ticks: DEFAULT_TIMEOUT_TICKS,
            stats: StopMachineStats {
                total_operations: 0,
                successful: 0,
                failed: 0,
                timeouts: 0,
                total_stopped_ticks: 0,
                max_stop_ticks: 0,
            },
        }
    }

    /// Update the facility's tick counter.
    pub fn update_tick(&mut self, tick: u64) {
        self.current_tick = tick;
    }

    /// Set the timeout for CPU acknowledgement.
    pub fn set_timeout(&mut self, ticks: u64) -> Result<()> {
        if ticks == 0 {
            return Err(Error::InvalidArgument);
        }
        self.timeout_ticks = ticks;
        Ok(())
    }

    // ── CPU management ─────────────────────────────────────────

    /// Register a CPU as online.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `cpu_id` is out of range.
    /// - [`Error::AlreadyExists`] if the CPU is already
    ///   registered.
    pub fn cpu_online(&mut self, cpu_id: u32) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if self.cpus[idx].active && self.cpus[idx].online {
            return Err(Error::AlreadyExists);
        }
        self.cpus[idx] = CpuStop {
            cpu_id,
            state: CpuStopState::Running,
            online: true,
            ack_tick: 0,
            active: true,
        };
        self.online_count = self.online_count.saturating_add(1);
        Ok(())
    }

    /// Mark a CPU as offline.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `cpu_id` is out of range.
    /// - [`Error::NotFound`] if the CPU is not registered.
    /// - [`Error::Busy`] if a stop-machine operation is in
    ///   progress.
    pub fn cpu_offline(&mut self, cpu_id: u32) -> Result<()> {
        if self.state != StopMachineState::Idle {
            return Err(Error::Busy);
        }
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if !self.cpus[idx].active || !self.cpus[idx].online {
            return Err(Error::NotFound);
        }
        self.cpus[idx].online = false;
        self.online_count = self.online_count.saturating_sub(1);
        Ok(())
    }

    /// Return the number of online CPUs.
    pub fn online_cpu_count(&self) -> u32 {
        self.online_count
    }

    // ── Work submission ────────────────────────────────────────

    /// Submit a work item to be executed under stop-machine
    /// protection.
    ///
    /// Returns the assigned work ID.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the work queue is full.
    pub fn submit_work(&mut self, callback_id: u32, arg: u64, target_cpu: u32) -> Result<u32> {
        let slot = self
            .work_queue
            .iter_mut()
            .find(|w| !w.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_work_id;
        self.next_work_id = self.next_work_id.wrapping_add(1);

        *slot = StopWork {
            id,
            callback_id,
            arg,
            target_cpu,
            active: true,
            completed: false,
            result_code: 0,
        };
        self.pending_count += 1;
        Ok(id)
    }

    /// Cancel a pending (not yet executing) work item.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the work ID is not found.
    /// - [`Error::Busy`] if the work is currently executing.
    pub fn cancel_work(&mut self, work_id: u32) -> Result<()> {
        let slot = self
            .work_queue
            .iter_mut()
            .find(|w| w.active && w.id == work_id)
            .ok_or(Error::NotFound)?;

        if slot.completed {
            return Err(Error::Busy);
        }

        slot.active = false;
        self.pending_count = self.pending_count.saturating_sub(1);
        Ok(())
    }

    // ── Stop-machine execution ─────────────────────────────────

    /// Initiate a stop-machine operation for the next pending
    /// work item.
    ///
    /// Transitions from `Idle` to `Requesting`. After calling
    /// this, the caller must send IPIs to all online CPUs and
    /// call [`cpu_ack`] as each CPU acknowledges.
    ///
    /// # Errors
    ///
    /// - [`Error::Busy`] if an operation is already in progress.
    /// - [`Error::NotFound`] if no work items are pending.
    pub fn begin_stop(&mut self) -> Result<u32> {
        if self.state != StopMachineState::Idle {
            return Err(Error::Busy);
        }
        // Find the first pending work item.
        let work = self
            .work_queue
            .iter()
            .find(|w| w.active && !w.completed)
            .ok_or(Error::NotFound)?;

        let work_id = work.id;

        // Choose the executor CPU.
        self.executor_cpu = if work.target_cpu != CPU_NONE {
            work.target_cpu
        } else {
            // Default to CPU 0 or the first online CPU.
            self.cpus
                .iter()
                .find(|c| c.active && c.online)
                .map(|c| c.cpu_id)
                .unwrap_or(0)
        };

        // Mark all non-executor online CPUs as needing to stop.
        for cpu in &mut self.cpus {
            if cpu.active && cpu.online {
                if cpu.cpu_id == self.executor_cpu {
                    cpu.state = CpuStopState::Stopped;
                    cpu.ack_tick = self.current_tick;
                } else {
                    cpu.state = CpuStopState::Stopping;
                }
            }
        }

        self.state = StopMachineState::Requesting;
        self.start_tick = self.current_tick;
        self.stats.total_operations = self.stats.total_operations.saturating_add(1);

        Ok(work_id)
    }

    /// Record that a CPU has acknowledged the stop request.
    ///
    /// When all online CPUs (except the executor) have
    /// acknowledged, the state transitions to `AllStopped`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `cpu_id` is out of range.
    /// - [`Error::InvalidArgument`] if the facility is not in
    ///   the `Requesting` state.
    pub fn cpu_ack(&mut self, cpu_id: u32) -> Result<bool> {
        if self.state != StopMachineState::Requesting {
            return Err(Error::InvalidArgument);
        }
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if !self.cpus[idx].active || !self.cpus[idx].online {
            return Err(Error::InvalidArgument);
        }

        self.cpus[idx].state = CpuStopState::Stopped;
        self.cpus[idx].ack_tick = self.current_tick;

        // Check whether all CPUs have stopped.
        let all_stopped = self
            .cpus
            .iter()
            .filter(|c| c.active && c.online)
            .all(|c| c.state == CpuStopState::Stopped);

        if all_stopped {
            self.state = StopMachineState::AllStopped;
        }

        Ok(all_stopped)
    }

    /// Check whether the operation has timed out.
    pub fn is_timed_out(&self) -> bool {
        if self.state != StopMachineState::Requesting {
            return false;
        }
        let elapsed = self.current_tick.saturating_sub(self.start_tick);
        elapsed >= self.timeout_ticks
    }

    /// Record that the work function has completed on the
    /// executor CPU.
    ///
    /// Returns a [`StopResult`] summarising the operation.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the facility is not in
    ///   the `AllStopped` state.
    pub fn work_done(&mut self, result_code: i32) -> Result<StopResult> {
        if self.state != StopMachineState::AllStopped {
            return Err(Error::InvalidArgument);
        }

        // Find and mark the work item as completed.
        let work = self
            .work_queue
            .iter_mut()
            .find(|w| w.active && !w.completed)
            .ok_or(Error::NotFound)?;

        work.completed = true;
        work.result_code = result_code;
        let work_id = work.id;

        let stop_duration = self.current_tick.saturating_sub(self.start_tick);
        let cpus_stopped = self
            .cpus
            .iter()
            .filter(|c| c.active && c.online && c.cpu_id != self.executor_cpu)
            .count() as u32;

        let result = StopResult {
            work_id,
            executor_cpu: self.executor_cpu,
            cpus_stopped,
            stop_duration_ticks: stop_duration,
            success: true,
            result_code,
        };

        self.stats.successful = self.stats.successful.saturating_add(1);
        self.stats.total_stopped_ticks =
            self.stats.total_stopped_ticks.saturating_add(stop_duration);
        if stop_duration > self.stats.max_stop_ticks {
            self.stats.max_stop_ticks = stop_duration;
        }

        self.state = StopMachineState::Done;
        Ok(result)
    }

    /// Release all CPUs and return to the idle state.
    ///
    /// Must be called after [`work_done`](Self::work_done) or
    /// after a timeout to allow the next operation to proceed.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the state does not allow
    ///   release (`Idle` or `Requesting` without timeout).
    pub fn release(&mut self) -> Result<()> {
        match self.state {
            StopMachineState::Done | StopMachineState::Failed => {}
            StopMachineState::Requesting if self.is_timed_out() => {
                self.stats.failed = self.stats.failed.saturating_add(1);
                self.stats.timeouts = self.stats.timeouts.saturating_add(1);
            }
            _ => return Err(Error::InvalidArgument),
        }

        // Resume all CPUs.
        for cpu in &mut self.cpus {
            if cpu.active && cpu.online {
                cpu.state = CpuStopState::Resumed;
            }
        }

        // Clean up completed work items.
        for work in &mut self.work_queue {
            if work.active && work.completed {
                work.active = false;
                self.pending_count = self.pending_count.saturating_sub(1);
            }
        }

        self.executor_cpu = CPU_NONE;
        self.state = StopMachineState::Idle;
        Ok(())
    }

    /// Abort a timed-out operation, recording the failure.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the facility is not in
    ///   a timed-out `Requesting` state.
    pub fn abort_timeout(&mut self) -> Result<()> {
        if !self.is_timed_out() {
            return Err(Error::InvalidArgument);
        }

        self.state = StopMachineState::Failed;

        // Mark the current work item as failed.
        if let Some(work) = self
            .work_queue
            .iter_mut()
            .find(|w| w.active && !w.completed)
        {
            work.completed = true;
            work.result_code = -1;
        }

        self.release()
    }

    // ── Queries ────────────────────────────────────────────────

    /// Return the current stop-machine state.
    pub fn state(&self) -> StopMachineState {
        self.state
    }

    /// Return the executor CPU for the current operation.
    pub fn executor_cpu(&self) -> u32 {
        self.executor_cpu
    }

    /// Return the number of pending work items.
    pub fn pending_work_count(&self) -> usize {
        self.pending_count
    }

    /// Return cumulative statistics.
    pub fn stats(&self) -> &StopMachineStats {
        &self.stats
    }

    /// Get the stop state of a specific CPU.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `cpu_id` is out of range.
    pub fn cpu_state(&self, cpu_id: u32) -> Result<CpuStopState> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.cpus[idx].state)
    }
}

impl core::fmt::Debug for StopMachine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StopMachine")
            .field("state", &self.state)
            .field("online_cpus", &self.online_count)
            .field("executor", &self.executor_cpu)
            .field("pending_work", &self.pending_count)
            .field("total_ops", &self.stats.total_operations)
            .finish()
    }
}
