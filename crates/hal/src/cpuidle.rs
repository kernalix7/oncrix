// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU idle state management subsystem.
//!
//! Provides a framework for managing processor idle states (C-states),
//! analogous to the Linux cpuidle subsystem but adapted for a no_std
//! microkernel environment.
//!
//! # Architecture
//!
//! - [`IdleState`] — descriptor for a single C-state (name, latency,
//!   residency requirement, power usage).
//! - [`IdleStateTable`] — per-CPU table of idle states (max 8: C0–C7).
//! - [`IdleGovernor`] — trait for idle state selection algorithms.
//! - [`MenuGovernor`] — governor with latency tolerance and predicted
//!   interval tracking.
//! - [`LadderGovernor`] — governor with promotion/demotion thresholds.
//! - [`CpuIdleDevice`] — per-CPU idle device with state table and stats.
//! - [`IdleStats`] — per-state usage counters and timing statistics.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of idle states (C0–C7).
const MAX_IDLE_STATES: usize = 8;

/// Maximum number of CPUs supported.
const MAX_IDLE_CPUS: usize = 64;

/// Default performance multiplier for the menu governor (scaled ×1000).
const MENU_PERF_MULT_DEFAULT: u32 = 1_000;

/// Latency tolerance in microseconds for the menu governor.
const MENU_LATENCY_TOLERANCE_US: u64 = 10_000;

/// Number of historical intervals tracked by the menu governor.
const MENU_INTERVALS: usize = 8;

/// Promotion threshold for the ladder governor (percent residency).
const LADDER_PROMOTION_PCT: u64 = 90;

/// Demotion threshold for the ladder governor (percent residency).
const LADDER_DEMOTION_PCT: u64 = 20;

// -------------------------------------------------------------------
// IdleState
// -------------------------------------------------------------------

/// Descriptor for a single CPU idle state (C-state).
#[derive(Debug, Clone, Copy)]
pub struct IdleState {
    /// Human-readable name stored as UTF-8 bytes (not NUL-terminated).
    pub name: [u8; 16],
    /// Number of valid bytes in [`name`](Self::name).
    pub name_len: usize,
    /// Exit latency in microseconds.
    pub latency_us: u32,
    /// Minimum residency time in microseconds for this state to be
    /// energy-beneficial.
    pub target_residency_us: u32,
    /// Relative power usage (arbitrary units; lower = less power).
    pub power_usage: u32,
    /// When `true`, this state is administratively disabled.
    pub disable: bool,
}

impl IdleState {
    /// Creates an idle state with the given parameters.
    pub fn new(name: &[u8], latency_us: u32, target_residency_us: u32, power_usage: u32) -> Self {
        let copy_len = name.len().min(16);
        let mut buf = [0u8; 16];
        buf[..copy_len].copy_from_slice(&name[..copy_len]);
        Self {
            name: buf,
            name_len: copy_len,
            latency_us,
            target_residency_us,
            power_usage,
            disable: false,
        }
    }
}

// -------------------------------------------------------------------
// IdleStats
// -------------------------------------------------------------------

/// Per-idle-state usage and timing statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct IdleStats {
    /// Total number of times this idle state was entered.
    pub usage_count: u64,
    /// Accumulated time spent in this state in microseconds.
    pub total_time_us: u64,
    /// Number of times residency was below the target threshold.
    pub below_threshold_count: u64,
    /// Number of times residency exceeded the target threshold.
    pub above_threshold_count: u64,
}

impl IdleStats {
    /// Records a single idle state exit with `residency_us` actual
    /// residency time.
    pub fn record(&mut self, residency_us: u64, target_residency_us: u32) {
        self.usage_count += 1;
        self.total_time_us = self.total_time_us.saturating_add(residency_us);
        if residency_us < u64::from(target_residency_us) {
            self.below_threshold_count += 1;
        } else {
            self.above_threshold_count += 1;
        }
    }

    /// Returns the average residency in microseconds.
    ///
    /// Returns `0` if the state has never been entered.
    pub fn average_residency_us(&self) -> u64 {
        self.total_time_us
            .checked_div(self.usage_count)
            .unwrap_or(0)
    }
}

// -------------------------------------------------------------------
// IdleStateTable
// -------------------------------------------------------------------

/// Table of idle states for a single CPU (max [`MAX_IDLE_STATES`]).
#[derive(Debug, Clone, Copy)]
pub struct IdleStateTable {
    /// Idle state descriptors.
    states: [Option<IdleState>; MAX_IDLE_STATES],
    /// Number of registered states.
    count: usize,
}

impl Default for IdleStateTable {
    fn default() -> Self {
        Self::new()
    }
}

impl IdleStateTable {
    /// Creates an empty idle state table.
    pub const fn new() -> Self {
        Self {
            states: [const { None }; MAX_IDLE_STATES],
            count: 0,
        }
    }

    /// Adds an idle state to the table.
    ///
    /// Returns [`Error::OutOfMemory`] when the table is full.
    pub fn add(&mut self, state: IdleState) -> Result<usize> {
        if self.count >= MAX_IDLE_STATES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.states[idx] = Some(state);
        self.count += 1;
        Ok(idx)
    }

    /// Returns a reference to the state at `index`.
    ///
    /// Returns [`Error::NotFound`] if the index is out of range or
    /// the slot is empty.
    pub fn get(&self, index: usize) -> Result<&IdleState> {
        if index >= MAX_IDLE_STATES {
            return Err(Error::NotFound);
        }
        self.states[index].as_ref().ok_or(Error::NotFound)
    }

    /// Returns a mutable reference to the state at `index`.
    ///
    /// Returns [`Error::NotFound`] if the index is out of range or
    /// the slot is empty.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut IdleState> {
        if index >= MAX_IDLE_STATES {
            return Err(Error::NotFound);
        }
        self.states[index].as_mut().ok_or(Error::NotFound)
    }

    /// Returns the number of registered idle states.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no idle states are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// -------------------------------------------------------------------
// IdleGovernor
// -------------------------------------------------------------------

/// Trait for idle state selection algorithms.
pub trait IdleGovernor {
    /// Select the best idle state index given a hint about how long
    /// the CPU is expected to remain idle (`idle_duration_hint_us`).
    ///
    /// Returns a state index in `0..count` or [`Error::NotFound`]
    /// if no suitable state is available.
    fn select_state(&mut self, table: &IdleStateTable, idle_duration_hint_us: u64)
    -> Result<usize>;
}

// -------------------------------------------------------------------
// MenuGovernor
// -------------------------------------------------------------------

/// Idle governor that chooses the deepest state whose exit latency
/// is within a latency tolerance and whose target residency is met
/// by the predicted idle duration.
///
/// Maintains a circular buffer of recent idle interval observations
/// to compute a predicted next idle interval.
#[derive(Debug, Clone, Copy)]
pub struct MenuGovernor {
    /// Performance multiplier (×1000; 1000 = 1.0).
    pub perf_multiplier: u32,
    /// Maximum acceptable exit latency in microseconds.
    pub latency_tolerance_us: u64,
    /// Ring buffer of recent idle intervals in microseconds.
    intervals: [u64; MENU_INTERVALS],
    /// Write index into the ring buffer.
    interval_ptr: usize,
    /// Number of valid entries in the ring buffer.
    interval_count: usize,
}

impl Default for MenuGovernor {
    fn default() -> Self {
        Self::new()
    }
}

impl MenuGovernor {
    /// Creates a new menu governor with default parameters.
    pub const fn new() -> Self {
        Self {
            perf_multiplier: MENU_PERF_MULT_DEFAULT,
            latency_tolerance_us: MENU_LATENCY_TOLERANCE_US,
            intervals: [0u64; MENU_INTERVALS],
            interval_ptr: 0,
            interval_count: 0,
        }
    }

    /// Records an observed idle interval for future predictions.
    pub fn record_interval(&mut self, duration_us: u64) {
        self.intervals[self.interval_ptr] = duration_us;
        self.interval_ptr = (self.interval_ptr + 1) % MENU_INTERVALS;
        if self.interval_count < MENU_INTERVALS {
            self.interval_count += 1;
        }
    }

    /// Computes the predicted next idle duration based on recent
    /// intervals (geometric mean approximated by arithmetic mean).
    fn predict_idle_us(&self) -> u64 {
        if self.interval_count == 0 {
            return 0;
        }
        let sum: u64 = self.intervals[..self.interval_count].iter().sum();
        sum / self.interval_count as u64
    }
}

impl IdleGovernor for MenuGovernor {
    fn select_state(
        &mut self,
        table: &IdleStateTable,
        idle_duration_hint_us: u64,
    ) -> Result<usize> {
        let predicted = self.predict_idle_us().max(idle_duration_hint_us);
        let effective = predicted.saturating_mul(u64::from(self.perf_multiplier)) / 1_000;

        let mut best: Option<usize> = None;
        for i in 0..table.len() {
            let state = table.get(i)?;
            if state.disable {
                continue;
            }
            if u64::from(state.latency_us) > self.latency_tolerance_us {
                continue;
            }
            if effective < u64::from(state.target_residency_us) {
                continue;
            }
            // Prefer deeper states (higher index).
            best = Some(i);
        }
        best.ok_or(Error::NotFound)
    }
}

// -------------------------------------------------------------------
// LadderGovernor
// -------------------------------------------------------------------

/// Idle governor that promotes to deeper states when residency is
/// consistently above threshold, and demotes to shallower states
/// when residency is below threshold.
#[derive(Debug, Clone, Copy, Default)]
pub struct LadderGovernor {
    /// Currently selected state index for promotion/demotion tracking.
    pub current_state: usize,
    /// Consecutive samples above promotion threshold.
    promotion_count: u32,
    /// Consecutive samples below demotion threshold.
    demotion_count: u32,
    /// Promotion count required to step up.
    pub promotion_threshold: u32,
    /// Demotion count required to step down.
    pub demotion_threshold: u32,
}

impl LadderGovernor {
    /// Creates a new ladder governor with default thresholds.
    pub const fn new() -> Self {
        Self {
            current_state: 0,
            promotion_count: 0,
            demotion_count: 0,
            promotion_threshold: 3,
            demotion_threshold: 1,
        }
    }

    /// Updates internal counters based on the last observed
    /// residency `last_residency_us` compared to the target for
    /// the previously selected state.
    pub fn update(&mut self, table: &IdleStateTable, last_residency_us: u64) -> Result<()> {
        let state = table.get(self.current_state)?;
        let target = u64::from(state.target_residency_us);
        let pct = last_residency_us
            .saturating_mul(100)
            .checked_div(target)
            .unwrap_or(100);

        if pct >= LADDER_PROMOTION_PCT {
            self.promotion_count = self.promotion_count.saturating_add(1);
            self.demotion_count = 0;
        } else if pct <= LADDER_DEMOTION_PCT {
            self.demotion_count = self.demotion_count.saturating_add(1);
            self.promotion_count = 0;
        } else {
            self.promotion_count = 0;
            self.demotion_count = 0;
        }

        let max_idx = table.len().saturating_sub(1);
        if self.promotion_count >= self.promotion_threshold && self.current_state < max_idx {
            self.current_state += 1;
            self.promotion_count = 0;
        } else if self.demotion_count >= self.demotion_threshold && self.current_state > 0 {
            self.current_state -= 1;
            self.demotion_count = 0;
        }

        Ok(())
    }
}

impl IdleGovernor for LadderGovernor {
    fn select_state(
        &mut self,
        table: &IdleStateTable,
        _idle_duration_hint_us: u64,
    ) -> Result<usize> {
        if table.is_empty() {
            return Err(Error::NotFound);
        }
        let idx = self.current_state.min(table.len() - 1);
        // Skip disabled states by moving toward shallower states.
        for i in (0..=idx).rev() {
            match table.get(i) {
                Ok(s) if !s.disable => return Ok(i),
                _ => continue,
            }
        }
        Err(Error::NotFound)
    }
}

// -------------------------------------------------------------------
// CpuIdleDevice
// -------------------------------------------------------------------

/// Per-CPU idle device managing idle state selection and statistics.
#[derive(Debug)]
pub struct CpuIdleDevice {
    /// Logical CPU identifier.
    pub cpu_id: u32,
    /// Table of supported idle states for this CPU.
    pub state_table: IdleStateTable,
    /// Per-state usage statistics.
    pub stats: [IdleStats; MAX_IDLE_STATES],
    /// Timestamp (µs) when the current idle period began.
    pub idle_start_us: u64,
    /// Residency (µs) of the last completed idle period.
    pub last_residency_us: u64,
    /// Index of the state currently entered (or last entered).
    pub current_state_idx: usize,
    /// Whether the CPU is currently in an idle state.
    pub in_idle: bool,
}

impl CpuIdleDevice {
    /// Creates a new idle device for `cpu_id`.
    pub const fn new(cpu_id: u32) -> Self {
        Self {
            cpu_id,
            state_table: IdleStateTable::new(),
            stats: [const {
                IdleStats {
                    usage_count: 0,
                    total_time_us: 0,
                    below_threshold_count: 0,
                    above_threshold_count: 0,
                }
            }; MAX_IDLE_STATES],
            idle_start_us: 0,
            last_residency_us: 0,
            current_state_idx: 0,
            in_idle: false,
        }
    }

    /// Enters idle state `state_idx` at time `now_us` (microseconds).
    ///
    /// Returns [`Error::NotFound`] if the state index is invalid or
    /// disabled, or [`Error::Busy`] if already in an idle state.
    pub fn enter(&mut self, state_idx: usize, now_us: u64) -> Result<()> {
        if self.in_idle {
            return Err(Error::Busy);
        }
        let state = self.state_table.get(state_idx)?;
        if state.disable {
            return Err(Error::NotFound);
        }
        self.current_state_idx = state_idx;
        self.idle_start_us = now_us;
        self.in_idle = true;
        Ok(())
    }

    /// Exits the current idle state at time `now_us` (microseconds).
    ///
    /// Returns the actual residency in microseconds and updates
    /// statistics for the exited state.
    ///
    /// Returns [`Error::InvalidArgument`] if the CPU is not in idle.
    pub fn exit(&mut self, now_us: u64) -> Result<u64> {
        if !self.in_idle {
            return Err(Error::InvalidArgument);
        }
        let residency = now_us.saturating_sub(self.idle_start_us);
        self.last_residency_us = residency;
        self.in_idle = false;

        let idx = self.current_state_idx;
        if idx < MAX_IDLE_STATES {
            if let Ok(state) = self.state_table.get(idx) {
                let target = state.target_residency_us;
                self.stats[idx].record(residency, target);
            }
        }
        Ok(residency)
    }
}

// -------------------------------------------------------------------
// CpuIdleRegistry
// -------------------------------------------------------------------

/// Registry managing per-CPU idle devices.
///
/// Supports up to [`MAX_IDLE_CPUS`] (64) CPUs.
pub struct CpuIdleRegistry {
    /// Per-CPU idle devices.
    devices: [Option<CpuIdleDevice>; MAX_IDLE_CPUS],
    /// Number of registered devices.
    count: usize,
}

impl Default for CpuIdleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuIdleRegistry {
    /// Creates a new, empty idle registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_IDLE_CPUS],
            count: 0,
        }
    }

    /// Registers an idle device for a CPU.
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id >= MAX_IDLE_CPUS`,
    /// or [`Error::AlreadyExists`] if a device for that CPU is already
    /// registered.
    pub fn register(&mut self, device: CpuIdleDevice) -> Result<()> {
        let idx = device.cpu_id as usize;
        if idx >= MAX_IDLE_CPUS {
            return Err(Error::InvalidArgument);
        }
        if self.devices[idx].is_some() {
            return Err(Error::AlreadyExists);
        }
        self.devices[idx] = Some(device);
        self.count += 1;
        Ok(())
    }

    /// Returns a shared reference to the idle device for `cpu_id`.
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn get(&self, cpu_id: u32) -> Result<&CpuIdleDevice> {
        let idx = cpu_id as usize;
        if idx < MAX_IDLE_CPUS {
            self.devices[idx].as_ref().ok_or(Error::NotFound)
        } else {
            Err(Error::NotFound)
        }
    }

    /// Returns a mutable reference to the idle device for `cpu_id`.
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn get_mut(&mut self, cpu_id: u32) -> Result<&mut CpuIdleDevice> {
        let idx = cpu_id as usize;
        if idx < MAX_IDLE_CPUS {
            self.devices[idx].as_mut().ok_or(Error::NotFound)
        } else {
            Err(Error::NotFound)
        }
    }

    /// Records idle state entry for `cpu_id`.
    ///
    /// Delegates to [`CpuIdleDevice::enter`].
    pub fn enter_idle_state(&mut self, cpu_id: u32, state_idx: usize, now_us: u64) -> Result<()> {
        self.get_mut(cpu_id)?.enter(state_idx, now_us)
    }

    /// Records idle state exit for `cpu_id`.
    ///
    /// Returns the actual residency in microseconds.
    /// Delegates to [`CpuIdleDevice::exit`].
    pub fn exit_idle_state(&mut self, cpu_id: u32, now_us: u64) -> Result<u64> {
        self.get_mut(cpu_id)?.exit(now_us)
    }

    /// Returns the number of registered idle devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no idle devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
