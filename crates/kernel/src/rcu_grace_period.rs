// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RCU grace period management.
//!
//! Manages RCU grace period lifecycle including starting, monitoring,
//! and completing grace periods. A grace period ensures that all CPUs
//! have passed through a quiescent state, allowing deferred memory
//! reclamation to proceed safely.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum CPUs tracked.
const MAX_CPUS: usize = 64;

/// Maximum pending callbacks.
const MAX_PENDING_CALLBACKS: usize = 512;

/// Maximum grace period log entries.
const MAX_GP_LOG: usize = 128;

/// Nanoseconds per millisecond.
const _NS_PER_MS: u64 = 1_000_000;

// ── Types ────────────────────────────────────────────────────────────

/// Grace period state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GracePeriodState {
    /// No grace period active.
    Idle,
    /// Grace period has started, waiting for quiescent states.
    WaitingForQs,
    /// All CPUs reported, finalizing.
    Finalizing,
    /// Grace period completed.
    Completed,
}

impl Default for GracePeriodState {
    fn default() -> Self {
        Self::Idle
    }
}

/// Per-CPU quiescent state tracking.
#[derive(Debug, Clone)]
pub struct CpuQsState {
    /// CPU identifier.
    cpu_id: u32,
    /// Whether this CPU reported a QS for the current GP.
    reported: bool,
    /// Timestamp of last QS report (nanoseconds).
    last_report_ns: u64,
    /// Total QS reports.
    total_reports: u64,
    /// Whether this CPU is online.
    online: bool,
}

impl CpuQsState {
    /// Creates a new CPU QS state.
    pub const fn new(cpu_id: u32) -> Self {
        Self {
            cpu_id,
            reported: false,
            last_report_ns: 0,
            total_reports: 0,
            online: true,
        }
    }

    /// Returns whether this CPU has reported.
    pub const fn has_reported(&self) -> bool {
        self.reported
    }

    /// Returns the CPU identifier.
    pub const fn cpu_id(&self) -> u32 {
        self.cpu_id
    }
}

/// A pending RCU callback awaiting grace period completion.
#[derive(Debug, Clone)]
pub struct RcuCallback {
    /// Callback identifier.
    callback_id: u64,
    /// Grace period number this callback is waiting for.
    gp_num: u64,
    /// Whether this callback has been executed.
    executed: bool,
    /// Registration timestamp.
    registered_ns: u64,
}

impl RcuCallback {
    /// Creates a new RCU callback.
    pub const fn new(callback_id: u64, gp_num: u64) -> Self {
        Self {
            callback_id,
            gp_num,
            executed: false,
            registered_ns: 0,
        }
    }

    /// Returns the callback identifier.
    pub const fn callback_id(&self) -> u64 {
        self.callback_id
    }
}

/// Grace period log entry.
#[derive(Debug, Clone)]
pub struct GracePeriodLog {
    /// Grace period number.
    gp_num: u64,
    /// Start timestamp.
    start_ns: u64,
    /// End timestamp (0 if still active).
    end_ns: u64,
    /// Duration in nanoseconds.
    duration_ns: u64,
    /// Number of callbacks processed.
    callbacks_processed: u32,
    /// Number of CPUs that participated.
    cpus_participated: u32,
}

impl GracePeriodLog {
    /// Creates a new log entry.
    pub const fn new(gp_num: u64, start_ns: u64) -> Self {
        Self {
            gp_num,
            start_ns,
            end_ns: 0,
            duration_ns: 0,
            callbacks_processed: 0,
            cpus_participated: 0,
        }
    }
}

/// Grace period statistics.
#[derive(Debug, Clone)]
pub struct GracePeriodStats {
    /// Total grace periods completed.
    pub total_completed: u64,
    /// Current grace period number.
    pub current_gp_num: u64,
    /// Average grace period duration (nanoseconds).
    pub avg_duration_ns: u64,
    /// Maximum grace period duration (nanoseconds).
    pub max_duration_ns: u64,
    /// Total callbacks processed.
    pub total_callbacks: u64,
    /// Currently pending callbacks.
    pub pending_callbacks: u32,
}

impl Default for GracePeriodStats {
    fn default() -> Self {
        Self::new()
    }
}

impl GracePeriodStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_completed: 0,
            current_gp_num: 0,
            avg_duration_ns: 0,
            max_duration_ns: 0,
            total_callbacks: 0,
            pending_callbacks: 0,
        }
    }
}

/// Central RCU grace period manager.
#[derive(Debug)]
pub struct GracePeriodManager {
    /// Per-CPU QS state.
    cpu_states: [Option<CpuQsState>; MAX_CPUS],
    /// Pending callbacks.
    callbacks: [Option<RcuCallback>; MAX_PENDING_CALLBACKS],
    /// Grace period log.
    gp_log: [Option<GracePeriodLog>; MAX_GP_LOG],
    /// Log write position.
    log_pos: usize,
    /// Number of CPUs.
    cpu_count: usize,
    /// Number of pending callbacks.
    callback_count: usize,
    /// Current grace period number.
    current_gp_num: u64,
    /// Current state.
    state: GracePeriodState,
    /// GP start timestamp.
    gp_start_ns: u64,
    /// Total completed GPs.
    total_completed: u64,
    /// Total callbacks processed.
    total_callbacks_processed: u64,
    /// Maximum GP duration.
    max_duration_ns: u64,
    /// Sum of all GP durations (for average).
    sum_duration_ns: u64,
    /// Next callback identifier.
    next_cb_id: u64,
}

impl Default for GracePeriodManager {
    fn default() -> Self {
        Self::new()
    }
}

impl GracePeriodManager {
    /// Creates a new grace period manager.
    pub const fn new() -> Self {
        Self {
            cpu_states: [const { None }; MAX_CPUS],
            callbacks: [const { None }; MAX_PENDING_CALLBACKS],
            gp_log: [const { None }; MAX_GP_LOG],
            log_pos: 0,
            cpu_count: 0,
            callback_count: 0,
            current_gp_num: 0,
            state: GracePeriodState::Idle,
            gp_start_ns: 0,
            total_completed: 0,
            total_callbacks_processed: 0,
            max_duration_ns: 0,
            sum_duration_ns: 0,
            next_cb_id: 1,
        }
    }

    /// Registers a CPU.
    pub fn register_cpu(&mut self, cpu_id: u32) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if self.cpu_states[idx].is_some() {
            return Err(Error::AlreadyExists);
        }
        self.cpu_states[idx] = Some(CpuQsState::new(cpu_id));
        self.cpu_count += 1;
        Ok(())
    }

    /// Starts a new grace period.
    pub fn start(&mut self, timestamp_ns: u64) -> Result<u64> {
        if self.state != GracePeriodState::Idle {
            return Err(Error::Busy);
        }
        self.current_gp_num += 1;
        self.state = GracePeriodState::WaitingForQs;
        self.gp_start_ns = timestamp_ns;
        // Reset QS reports.
        for cpu in self.cpu_states.iter_mut().flatten() {
            cpu.reported = false;
        }
        let log = GracePeriodLog::new(self.current_gp_num, timestamp_ns);
        self.gp_log[self.log_pos] = Some(log);
        Ok(self.current_gp_num)
    }

    /// Reports a quiescent state from a CPU.
    pub fn report_qs(&mut self, cpu_id: u32, timestamp_ns: u64) -> Result<bool> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let cpu = self.cpu_states[idx].as_mut().ok_or(Error::NotFound)?;
        cpu.reported = true;
        cpu.last_report_ns = timestamp_ns;
        cpu.total_reports += 1;
        // Check if all online CPUs have reported.
        let all_reported = self
            .cpu_states
            .iter()
            .flatten()
            .filter(|c| c.online)
            .all(|c| c.reported);
        if all_reported {
            self.state = GracePeriodState::Finalizing;
        }
        Ok(all_reported)
    }

    /// Completes the current grace period.
    pub fn complete(&mut self, timestamp_ns: u64) -> Result<u32> {
        if self.state != GracePeriodState::Finalizing {
            return Err(Error::InvalidArgument);
        }
        let duration = timestamp_ns.saturating_sub(self.gp_start_ns);
        if duration > self.max_duration_ns {
            self.max_duration_ns = duration;
        }
        self.sum_duration_ns += duration;
        self.total_completed += 1;
        // Process pending callbacks.
        let gp = self.current_gp_num;
        let mut processed = 0u32;
        for slot in self.callbacks.iter_mut() {
            if let Some(cb) = slot {
                if cb.gp_num <= gp && !cb.executed {
                    cb.executed = true;
                    processed += 1;
                }
            }
        }
        // Remove executed callbacks.
        for slot in self.callbacks.iter_mut() {
            if slot.as_ref().map_or(false, |cb| cb.executed) {
                *slot = None;
                self.callback_count -= 1;
            }
        }
        self.total_callbacks_processed += processed as u64;
        // Update log.
        if let Some(log) = &mut self.gp_log[self.log_pos] {
            log.end_ns = timestamp_ns;
            log.duration_ns = duration;
            log.callbacks_processed = processed;
        }
        self.log_pos = (self.log_pos + 1) % MAX_GP_LOG;
        self.state = GracePeriodState::Idle;
        Ok(processed)
    }

    /// Queues a callback to run after the next grace period.
    pub fn queue_callback(&mut self) -> Result<u64> {
        if self.callback_count >= MAX_PENDING_CALLBACKS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_cb_id;
        self.next_cb_id += 1;
        let gp = self.current_gp_num + 1;
        let cb = RcuCallback::new(id, gp);
        if let Some(slot) = self.callbacks.iter_mut().find(|s| s.is_none()) {
            *slot = Some(cb);
            self.callback_count += 1;
            Ok(id)
        } else {
            Err(Error::OutOfMemory)
        }
    }

    /// Returns the current grace period state.
    pub const fn state(&self) -> GracePeriodState {
        self.state
    }

    /// Returns statistics.
    pub fn stats(&self) -> GracePeriodStats {
        let avg = if self.total_completed > 0 {
            self.sum_duration_ns / self.total_completed
        } else {
            0
        };
        GracePeriodStats {
            total_completed: self.total_completed,
            current_gp_num: self.current_gp_num,
            avg_duration_ns: avg,
            max_duration_ns: self.max_duration_ns,
            total_callbacks: self.total_callbacks_processed,
            pending_callbacks: self.callback_count as u32,
        }
    }

    /// Returns the number of managed CPUs.
    pub const fn cpu_count(&self) -> usize {
        self.cpu_count
    }
}
