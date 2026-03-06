// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU idle governor — idle state management and power-aware idle selection.
//!
//! Manages CPU idle states (C-states) and implements multiple governor
//! algorithms to select the optimal idle state based on predicted sleep
//! duration, timer events, and recent activity patterns.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                   CpuIdleSubsystem                           │
//! │                                                              │
//! │  IdleDriver[0..MAX_CPUS]  (per-CPU idle state drivers)       │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  states: [IdleState; MAX_IDLE_STATES]                  │  │
//! │  │  state_count / deepest_state                           │  │
//! │  │  current_state / enabled                               │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  IdleGovernor { Menu | Ladder | TEO }                        │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  MenuGovernor: predicted_us, correction, buckets       │  │
//! │  │  LadderGovernor: ladder_threshold, demotion counters   │  │
//! │  │  TeoGovernor: timer intercepts, hit/miss tracking      │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  CpuIdleStats (global counters)                              │
//! │  - per-state usage, total idle time, wrong predictions       │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Governors
//!
//! - **Menu**: Predicts sleep duration using recent intervals and a
//!   correction factor, selects the deepest state whose exit latency
//!   fits within the predicted window.
//! - **Ladder**: Conservative step-up/step-down approach; promotes
//!   to deeper states only after repeated successes.
//! - **TEO** (Timer Events Oriented): Uses upcoming timer events
//!   to bound the idle duration, avoiding overshoot into deep
//!   states when a near timer is pending.
//!
//! # Reference
//!
//! Linux `drivers/cpuidle/`, `include/linux/cpuidle.h`,
//! `Documentation/admin-guide/pm/cpuidle.rst`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum number of idle states per CPU.
const MAX_IDLE_STATES: usize = 8;

/// Maximum CPUs supported.
const MAX_CPUS: usize = 8;

/// Idle state name buffer length.
const IDLE_NAME_LEN: usize = 16;

/// Number of recent-interval buckets for the Menu governor.
const MENU_BUCKETS: usize = 12;

/// Number of recent intervals tracked by the Menu governor.
const MENU_INTERVALS: usize = 8;

/// Ladder governor: consecutive successes needed to promote.
const LADDER_PROMOTION_COUNT: u32 = 4;

/// Ladder governor: consecutive failures needed to demote.
const LADDER_DEMOTION_COUNT: u32 = 1;

/// TEO governor: number of recent timer intercepts to track.
const TEO_INTERCEPTS: usize = 8;

/// Default correction factor (fixed-point, 1024 = 1.0).
const CORRECTION_FACTOR_UNIT: u32 = 1024;

// ══════════════════════════════════════════════════════════════
// IdleState
// ══════════════════════════════════════════════════════════════

/// A single CPU idle state (C-state) descriptor.
///
/// Each idle state has a characteristic exit latency, target
/// residency, and power consumption.  The CPU must remain idle
/// for at least `target_residency_us` for the state to be
/// worthwhile (the energy saved offsets the entry/exit cost).
#[derive(Clone, Copy)]
pub struct IdleState {
    /// Human-readable state name (e.g., `C0`, `C1`, `C3`).
    pub name: [u8; IDLE_NAME_LEN],
    /// Time in microseconds to return from this state to C0.
    pub exit_latency_us: u32,
    /// Minimum residency in microseconds for net energy gain.
    pub target_residency_us: u32,
    /// Estimated power usage in microwatts while in this state.
    pub power_usage_uw: u32,
    /// Number of times this state has been entered.
    pub usage_count: u64,
    /// Cumulative time spent in this state (microseconds).
    pub total_time_us: u64,
    /// Whether this state is currently enabled.
    pub enabled: bool,
}

impl IdleState {
    /// Create a new idle state with default values.
    pub const fn new() -> Self {
        Self {
            name: [0u8; IDLE_NAME_LEN],
            exit_latency_us: 0,
            target_residency_us: 0,
            power_usage_uw: 0,
            usage_count: 0,
            total_time_us: 0,
            enabled: false,
        }
    }

    /// Create a named idle state with specified characteristics.
    pub fn with_params(
        name: &[u8],
        exit_latency_us: u32,
        target_residency_us: u32,
        power_usage_uw: u32,
    ) -> Self {
        let mut state = Self::new();
        let copy_len = name.len().min(IDLE_NAME_LEN);
        state.name[..copy_len].copy_from_slice(&name[..copy_len]);
        state.exit_latency_us = exit_latency_us;
        state.target_residency_us = target_residency_us;
        state.power_usage_uw = power_usage_uw;
        state.enabled = true;
        state
    }
}

impl Default for IdleState {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// IdleDriver
// ══════════════════════════════════════════════════════════════

/// Per-CPU idle driver managing available idle states.
///
/// Each CPU has its own driver that tracks which idle states
/// are available, the current state, and the deepest permitted
/// state.
#[derive(Clone, Copy)]
pub struct IdleDriver {
    /// Available idle states, ordered from shallowest to deepest.
    pub states: [IdleState; MAX_IDLE_STATES],
    /// Number of registered idle states.
    pub state_count: u8,
    /// Index of the deepest permitted state.
    pub deepest_state: u8,
    /// Currently active idle state index (0 = running / C0).
    pub current_state: u8,
    /// Whether this driver is enabled.
    pub enabled: bool,
    /// CPU ID for this driver.
    pub cpu_id: u32,
    /// Tick when the CPU last entered idle.
    pub idle_entry_tick: u64,
    /// Tick when the CPU last exited idle.
    pub idle_exit_tick: u64,
}

impl IdleDriver {
    /// Create a new idle driver for the given CPU.
    pub const fn new() -> Self {
        Self {
            states: [const { IdleState::new() }; MAX_IDLE_STATES],
            state_count: 0,
            deepest_state: 0,
            current_state: 0,
            enabled: false,
            cpu_id: 0,
            idle_entry_tick: 0,
            idle_exit_tick: 0,
        }
    }

    /// Register a new idle state with this driver.
    pub fn register_state(&mut self, state: IdleState) -> Result<u8> {
        if self.state_count as usize >= MAX_IDLE_STATES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.state_count;
        self.states[idx as usize] = state;
        self.state_count += 1;
        self.deepest_state = idx;
        Ok(idx)
    }

    /// Enable or disable a specific idle state.
    pub fn set_state_enabled(&mut self, state_idx: u8, enabled: bool) -> Result<()> {
        if state_idx >= self.state_count {
            return Err(Error::InvalidArgument);
        }
        self.states[state_idx as usize].enabled = enabled;
        // Recalculate deepest enabled state.
        self.deepest_state = 0;
        for i in (0..self.state_count as usize).rev() {
            if self.states[i].enabled {
                self.deepest_state = i as u8;
                break;
            }
        }
        Ok(())
    }

    /// Get the exit latency of a specific state.
    pub fn state_latency(&self, state_idx: u8) -> Result<u32> {
        if state_idx >= self.state_count {
            return Err(Error::InvalidArgument);
        }
        Ok(self.states[state_idx as usize].exit_latency_us)
    }
}

impl Default for IdleDriver {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// IdleGovernor
// ══════════════════════════════════════════════════════════════

/// Idle governor algorithm selector.
///
/// Each governor uses a different strategy to predict how long
/// the CPU will remain idle and select an appropriate C-state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleGovernorType {
    /// Menu governor — prediction-based, uses recent intervals
    /// and correction factor.
    Menu,
    /// Ladder governor — conservative step-up/step-down.
    Ladder,
    /// Timer Events Oriented — uses upcoming timer events
    /// to bound idle duration.
    Teo,
}

impl Default for IdleGovernorType {
    fn default() -> Self {
        Self::Menu
    }
}

// ══════════════════════════════════════════════════════════════
// MenuGovernor
// ══════════════════════════════════════════════════════════════

/// Menu governor state — prediction-based idle state selection.
///
/// Maintains a rolling window of recent idle intervals and a
/// correction factor to refine predictions.  Buckets divide
/// intervals into exponential ranges for fast histogram lookup.
#[derive(Clone, Copy)]
pub struct MenuGovernor {
    /// Predicted idle duration in microseconds.
    pub predicted_us: u64,
    /// Correction factor (fixed-point; `CORRECTION_FACTOR_UNIT` = 1.0).
    pub correction_factor: u32,
    /// Recent intervals (microseconds) for prediction.
    pub intervals: [u64; MENU_INTERVALS],
    /// Write index into the intervals ring buffer.
    pub interval_idx: usize,
    /// Bucket hit counts (exponential ranges).
    pub bucket_counts: [u32; MENU_BUCKETS],
    /// Typical interval derived from histogram mode.
    pub typical_interval: u64,
    /// Total predictions made.
    pub total_predictions: u64,
    /// Total incorrect predictions (actual << predicted).
    pub wrong_predictions: u64,
}

impl MenuGovernor {
    /// Create a new Menu governor with default settings.
    pub const fn new() -> Self {
        Self {
            predicted_us: 0,
            correction_factor: CORRECTION_FACTOR_UNIT,
            intervals: [0u64; MENU_INTERVALS],
            interval_idx: 0,
            bucket_counts: [0u32; MENU_BUCKETS],
            typical_interval: 0,
            total_predictions: 0,
            wrong_predictions: 0,
        }
    }

    /// Record an observed idle interval and update statistics.
    pub fn record_interval(&mut self, actual_us: u64) {
        self.intervals[self.interval_idx] = actual_us;
        self.interval_idx = (self.interval_idx + 1) % MENU_INTERVALS;

        // Update bucket count.
        let bucket = Self::interval_to_bucket(actual_us);
        self.bucket_counts[bucket] = self.bucket_counts[bucket].saturating_add(1);

        // Recompute typical interval from histogram mode.
        self.typical_interval = self.compute_typical();
    }

    /// Predict the next idle duration.
    pub fn predict(&mut self) -> u64 {
        // Weighted average of recent intervals, scaled by
        // the correction factor.
        let avg = self.average_interval();
        let corrected =
            (avg as u128 * self.correction_factor as u128) / CORRECTION_FACTOR_UNIT as u128;
        self.predicted_us = corrected as u64;
        self.total_predictions += 1;
        self.predicted_us
    }

    /// Update the correction factor after observing actual idle time.
    pub fn update_correction(&mut self, actual_us: u64) {
        if self.predicted_us == 0 {
            return;
        }
        // Exponential moving average of ratio actual/predicted.
        let ratio = if actual_us > self.predicted_us {
            // Under-predicted — increase factor.
            let r = (actual_us * CORRECTION_FACTOR_UNIT as u64) / self.predicted_us;
            r.min(CORRECTION_FACTOR_UNIT as u64 * 2) as u32
        } else {
            // Over-predicted — decrease factor.
            let r = (actual_us * CORRECTION_FACTOR_UNIT as u64) / self.predicted_us;
            r.max(CORRECTION_FACTOR_UNIT as u32 as u64 / 2) as u32
        };
        // EMA: new = old * 7/8 + sample * 1/8
        self.correction_factor = (self.correction_factor * 7 + ratio) / 8;

        if actual_us < self.predicted_us / 2 {
            self.wrong_predictions += 1;
        }
    }

    /// Map an interval to a bucket index (exponential ranges).
    fn interval_to_bucket(us: u64) -> usize {
        // Buckets: 0-1, 1-2, 2-4, 4-8, ... 1024-2048, 2048+
        if us == 0 {
            return 0;
        }
        let log2 = 63 - us.leading_zeros();
        (log2 as usize).min(MENU_BUCKETS - 1)
    }

    /// Compute the average of recent intervals.
    fn average_interval(&self) -> u64 {
        let sum: u64 = self.intervals.iter().sum();
        let count = self.intervals.iter().filter(|&&v| v > 0).count();
        if count == 0 {
            return 0;
        }
        sum / count as u64
    }

    /// Find the typical interval from histogram mode.
    fn compute_typical(&self) -> u64 {
        let mut max_count = 0u32;
        let mut max_bucket = 0usize;
        for (i, &count) in self.bucket_counts.iter().enumerate() {
            if count > max_count {
                max_count = count;
                max_bucket = i;
            }
        }
        // Return midpoint of the winning bucket.
        if max_bucket == 0 {
            1
        } else {
            1u64 << max_bucket
        }
    }
}

impl Default for MenuGovernor {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// LadderGovernor
// ══════════════════════════════════════════════════════════════

/// Per-state ladder governor tracking for one CPU.
#[derive(Clone, Copy)]
pub struct LadderStateInfo {
    /// Consecutive successful residencies at this level.
    pub promotion_count: u32,
    /// Consecutive early wakeups at this level.
    pub demotion_count: u32,
    /// Promotion threshold (microseconds).
    pub promotion_threshold_us: u64,
    /// Demotion threshold (microseconds).
    pub demotion_threshold_us: u64,
}

impl LadderStateInfo {
    /// Create ladder state info with default thresholds.
    pub const fn new() -> Self {
        Self {
            promotion_count: 0,
            demotion_count: 0,
            promotion_threshold_us: 0,
            demotion_threshold_us: 0,
        }
    }
}

impl Default for LadderStateInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Ladder governor state — conservative step-up/step-down.
///
/// Promotes to deeper states only after repeated successes;
/// demotes immediately on early wakeup.
#[derive(Clone, Copy)]
pub struct LadderGovernor {
    /// Per-state ladder tracking.
    pub state_info: [LadderStateInfo; MAX_IDLE_STATES],
    /// Current recommended state index per CPU.
    pub current_level: [u8; MAX_CPUS],
}

impl LadderGovernor {
    /// Create a new Ladder governor.
    pub const fn new() -> Self {
        Self {
            state_info: [const { LadderStateInfo::new() }; MAX_IDLE_STATES],
            current_level: [0u8; MAX_CPUS],
        }
    }

    /// Initialize ladder thresholds from an idle driver's states.
    pub fn init_from_driver(&mut self, driver: &IdleDriver) {
        for i in 0..driver.state_count as usize {
            let state = &driver.states[i];
            self.state_info[i].promotion_threshold_us = state.target_residency_us as u64;
            self.state_info[i].demotion_threshold_us = state.exit_latency_us as u64;
        }
    }

    /// Select a state for the given CPU based on actual residency.
    pub fn select(&mut self, cpu: usize, last_residency_us: u64, max_state: u8) -> u8 {
        if cpu >= MAX_CPUS {
            return 0;
        }
        let level = self.current_level[cpu] as usize;

        if level < max_state as usize {
            let info = &self.state_info[level];
            if last_residency_us >= info.promotion_threshold_us {
                self.state_info[level].promotion_count += 1;
                self.state_info[level].demotion_count = 0;
                if self.state_info[level].promotion_count >= LADDER_PROMOTION_COUNT {
                    self.current_level[cpu] += 1;
                    self.state_info[level].promotion_count = 0;
                }
            } else {
                self.state_info[level].demotion_count += 1;
                self.state_info[level].promotion_count = 0;
            }
        }

        if level > 0 {
            let info = &self.state_info[level];
            if last_residency_us < info.demotion_threshold_us {
                if info.demotion_count >= LADDER_DEMOTION_COUNT {
                    self.current_level[cpu] -= 1;
                    self.state_info[level].demotion_count = 0;
                }
            }
        }

        self.current_level[cpu]
    }
}

impl Default for LadderGovernor {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// TeoGovernor
// ══════════════════════════════════════════════════════════════

/// TEO intercept record — timer event that shortened idle.
#[derive(Clone, Copy)]
pub struct TeoIntercept {
    /// State that was targeted before the timer fired.
    pub target_state: u8,
    /// Actual residency before the timer event (microseconds).
    pub actual_residency_us: u64,
    /// Whether the timer intercept was from a known event.
    pub from_timer: bool,
}

impl TeoIntercept {
    /// Create an empty TEO intercept record.
    pub const fn new() -> Self {
        Self {
            target_state: 0,
            actual_residency_us: 0,
            from_timer: false,
        }
    }
}

impl Default for TeoIntercept {
    fn default() -> Self {
        Self::new()
    }
}

/// Timer Events Oriented governor state.
///
/// Uses upcoming timer events to bound the idle duration,
/// avoiding deep states when a near timer is pending.
#[derive(Clone, Copy)]
pub struct TeoGovernor {
    /// Recent intercept history.
    pub intercepts: [TeoIntercept; TEO_INTERCEPTS],
    /// Write index into the intercepts ring.
    pub intercept_idx: usize,
    /// Per-state hit count (timer arrived after full residency).
    pub hits: [u32; MAX_IDLE_STATES],
    /// Per-state miss count (woken early by timer).
    pub misses: [u32; MAX_IDLE_STATES],
    /// Next known timer event in microseconds from now.
    pub next_timer_us: u64,
}

impl TeoGovernor {
    /// Create a new TEO governor.
    pub const fn new() -> Self {
        Self {
            intercepts: [const { TeoIntercept::new() }; TEO_INTERCEPTS],
            intercept_idx: 0,
            hits: [0u32; MAX_IDLE_STATES],
            misses: [0u32; MAX_IDLE_STATES],
            next_timer_us: u64::MAX,
        }
    }

    /// Set the next expected timer event.
    pub fn set_next_timer(&mut self, us_from_now: u64) {
        self.next_timer_us = us_from_now;
    }

    /// Select state bounded by the next timer event.
    pub fn select(&self, driver: &IdleDriver) -> u8 {
        let mut best = 0u8;
        for i in 0..driver.state_count as usize {
            if !driver.states[i].enabled {
                continue;
            }
            let state = &driver.states[i];
            // The state's target residency must fit within
            // the time until the next timer event.
            if (state.target_residency_us as u64) > self.next_timer_us {
                break;
            }
            // Prefer states with better hit ratio.
            let total = self.hits[i] + self.misses[i];
            if total > 0 && self.misses[i] > self.hits[i] {
                // Too many misses — skip this state.
                continue;
            }
            best = i as u8;
        }
        best
    }

    /// Record the result of an idle period.
    pub fn record(&mut self, target_state: u8, actual_residency_us: u64, target_residency_us: u64) {
        let idx = target_state as usize;
        if idx < MAX_IDLE_STATES {
            if actual_residency_us >= target_residency_us {
                self.hits[idx] = self.hits[idx].saturating_add(1);
            } else {
                self.misses[idx] = self.misses[idx].saturating_add(1);
            }
        }

        // Record intercept.
        self.intercepts[self.intercept_idx] = TeoIntercept {
            target_state,
            actual_residency_us,
            from_timer: actual_residency_us < target_residency_us,
        };
        self.intercept_idx = (self.intercept_idx + 1) % TEO_INTERCEPTS;
    }
}

impl Default for TeoGovernor {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// CpuIdleStats
// ══════════════════════════════════════════════════════════════

/// Global CPU idle statistics.
#[derive(Clone, Copy)]
pub struct CpuIdleStats {
    /// Per-state usage counts (across all CPUs).
    pub state_usage: [u64; MAX_IDLE_STATES],
    /// Per-state total time in microseconds.
    pub state_total_us: [u64; MAX_IDLE_STATES],
    /// Total time spent in any idle state (microseconds).
    pub total_idle_us: u64,
    /// Number of idle entries (across all CPUs).
    pub total_entries: u64,
    /// Number of wrong predictions (actual << predicted).
    pub wrong_predictions: u64,
    /// Number of governor overrides (driver rejected selection).
    pub governor_overrides: u64,
}

impl CpuIdleStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            state_usage: [0u64; MAX_IDLE_STATES],
            state_total_us: [0u64; MAX_IDLE_STATES],
            total_idle_us: 0,
            total_entries: 0,
            wrong_predictions: 0,
            governor_overrides: 0,
        }
    }

    /// Record entry into an idle state.
    pub fn record_entry(&mut self, state_idx: u8) {
        if (state_idx as usize) < MAX_IDLE_STATES {
            self.state_usage[state_idx as usize] += 1;
            self.total_entries += 1;
        }
    }

    /// Record exit from an idle state with duration.
    pub fn record_exit(&mut self, state_idx: u8, duration_us: u64) {
        if (state_idx as usize) < MAX_IDLE_STATES {
            self.state_total_us[state_idx as usize] += duration_us;
            self.total_idle_us += duration_us;
        }
    }
}

impl Default for CpuIdleStats {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// CpuIdleSubsystem
// ══════════════════════════════════════════════════════════════

/// CPU idle subsystem — manages all per-CPU idle drivers,
/// the active governor, and global statistics.
pub struct CpuIdleSubsystem {
    /// Per-CPU idle drivers.
    pub drivers: [IdleDriver; MAX_CPUS],
    /// Active governor type.
    pub governor_type: IdleGovernorType,
    /// Menu governor state (used when `governor_type == Menu`).
    pub menu: MenuGovernor,
    /// Ladder governor state (used when `governor_type == Ladder`).
    pub ladder: LadderGovernor,
    /// TEO governor state (used when `governor_type == Teo`).
    pub teo: TeoGovernor,
    /// Global statistics.
    pub stats: CpuIdleStats,
    /// Number of registered CPUs.
    pub cpu_count: u32,
    /// Whether the subsystem is initialized.
    pub initialized: bool,
}

impl CpuIdleSubsystem {
    /// Create a new CPU idle subsystem with default settings.
    pub const fn new() -> Self {
        Self {
            drivers: [const { IdleDriver::new() }; MAX_CPUS],
            governor_type: IdleGovernorType::Menu,
            menu: MenuGovernor::new(),
            ladder: LadderGovernor::new(),
            teo: TeoGovernor::new(),
            stats: CpuIdleStats::new(),
            cpu_count: 0,
            initialized: false,
        }
    }

    /// Initialize the subsystem for a given number of CPUs.
    pub fn init(&mut self, cpu_count: u32) -> Result<()> {
        if cpu_count == 0 || cpu_count as usize > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.cpu_count = cpu_count;
        for i in 0..cpu_count as usize {
            self.drivers[i].cpu_id = i as u32;
            self.drivers[i].enabled = true;
        }
        self.initialized = true;
        Ok(())
    }

    /// Set the active governor.
    pub fn set_governor(&mut self, gov: IdleGovernorType) -> Result<()> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        self.governor_type = gov;
        // Re-initialize ladder thresholds if switching to Ladder.
        if gov == IdleGovernorType::Ladder {
            for i in 0..self.cpu_count as usize {
                self.ladder.init_from_driver(&self.drivers[i]);
            }
        }
        Ok(())
    }

    /// Register an idle state for a specific CPU.
    pub fn register_state(&mut self, cpu: u32, state: IdleState) -> Result<u8> {
        if cpu >= self.cpu_count {
            return Err(Error::InvalidArgument);
        }
        self.drivers[cpu as usize].register_state(state)
    }

    /// Select the optimal idle state for a CPU.
    ///
    /// Uses the active governor to predict idle duration and
    /// select the deepest appropriate state.
    pub fn select_state(&mut self, cpu: u32, latency_limit_us: u32) -> Result<u8> {
        if cpu >= self.cpu_count {
            return Err(Error::InvalidArgument);
        }
        let driver = &self.drivers[cpu as usize];
        if driver.state_count == 0 {
            return Err(Error::NotFound);
        }

        let selected = match self.governor_type {
            IdleGovernorType::Menu => {
                let predicted = self.menu.predict();
                self.find_best_state(cpu, predicted, latency_limit_us)
            }
            IdleGovernorType::Ladder => {
                let last_residency = self.compute_last_residency(cpu);
                self.ladder
                    .select(cpu as usize, last_residency, driver.deepest_state)
            }
            IdleGovernorType::Teo => self.teo.select(driver),
        };

        // Clamp to latency limit.
        let final_state = self.clamp_to_latency(cpu, selected, latency_limit_us);

        if final_state != selected {
            self.stats.governor_overrides += 1;
        }

        Ok(final_state)
    }

    /// Enter the selected idle state on a CPU.
    pub fn enter_state(&mut self, cpu: u32, state_idx: u8, current_tick: u64) -> Result<()> {
        if cpu >= self.cpu_count {
            return Err(Error::InvalidArgument);
        }
        let driver = &mut self.drivers[cpu as usize];
        if state_idx >= driver.state_count {
            return Err(Error::InvalidArgument);
        }

        driver.current_state = state_idx;
        driver.idle_entry_tick = current_tick;
        driver.states[state_idx as usize].usage_count += 1;

        self.stats.record_entry(state_idx);
        Ok(())
    }

    /// Exit the current idle state on a CPU.
    pub fn exit_state(&mut self, cpu: u32, current_tick: u64, tick_period_us: u64) -> Result<u64> {
        if cpu >= self.cpu_count {
            return Err(Error::InvalidArgument);
        }
        let driver = &mut self.drivers[cpu as usize];
        let state_idx = driver.current_state;
        let entry_tick = driver.idle_entry_tick;

        let elapsed_ticks = current_tick.saturating_sub(entry_tick);
        let duration_us = elapsed_ticks.saturating_mul(tick_period_us);

        driver.states[state_idx as usize].total_time_us += duration_us;
        driver.idle_exit_tick = current_tick;
        driver.current_state = 0;

        self.stats.record_exit(state_idx, duration_us);
        Ok(duration_us)
    }

    /// Reflect after wakeup — update governor with actual idle duration.
    pub fn reflect(&mut self, cpu: u32, actual_us: u64) -> Result<()> {
        if cpu >= self.cpu_count {
            return Err(Error::InvalidArgument);
        }
        let state_idx = self.drivers[cpu as usize].current_state;

        match self.governor_type {
            IdleGovernorType::Menu => {
                self.menu.record_interval(actual_us);
                self.menu.update_correction(actual_us);
                if actual_us < self.menu.predicted_us / 2 {
                    self.stats.wrong_predictions += 1;
                }
            }
            IdleGovernorType::Ladder => {
                // Ladder is updated during select.
            }
            IdleGovernorType::Teo => {
                let target_residency = if (state_idx as usize) < MAX_IDLE_STATES {
                    self.drivers[cpu as usize].states[state_idx as usize].target_residency_us as u64
                } else {
                    0
                };
                self.teo.record(state_idx, actual_us, target_residency);
            }
        }
        Ok(())
    }

    /// Get statistics for a specific idle state.
    pub fn state_stats(&self, state_idx: u8) -> Result<(u64, u64)> {
        if state_idx as usize >= MAX_IDLE_STATES {
            return Err(Error::InvalidArgument);
        }
        Ok((
            self.stats.state_usage[state_idx as usize],
            self.stats.state_total_us[state_idx as usize],
        ))
    }

    /// Get global idle statistics.
    pub fn global_stats(&self) -> &CpuIdleStats {
        &self.stats
    }

    /// Reset all statistics.
    pub fn reset_stats(&mut self) {
        self.stats = CpuIdleStats::new();
        self.menu.total_predictions = 0;
        self.menu.wrong_predictions = 0;
        for driver in &mut self.drivers[..self.cpu_count as usize] {
            for state in &mut driver.states[..driver.state_count as usize] {
                state.usage_count = 0;
                state.total_time_us = 0;
            }
        }
    }

    /// Find the best state for a predicted duration and latency limit.
    fn find_best_state(&self, cpu: u32, predicted_us: u64, latency_limit_us: u32) -> u8 {
        let driver = &self.drivers[cpu as usize];
        let mut best = 0u8;
        for i in 0..driver.state_count as usize {
            if !driver.states[i].enabled {
                continue;
            }
            let state = &driver.states[i];
            if state.exit_latency_us > latency_limit_us {
                break;
            }
            if (state.target_residency_us as u64) > predicted_us {
                break;
            }
            best = i as u8;
        }
        best
    }

    /// Clamp a selected state to the latency limit.
    fn clamp_to_latency(&self, cpu: u32, state_idx: u8, latency_limit_us: u32) -> u8 {
        let driver = &self.drivers[cpu as usize];
        let mut clamped = state_idx;
        while clamped > 0 && driver.states[clamped as usize].exit_latency_us > latency_limit_us {
            clamped -= 1;
        }
        clamped
    }

    /// Compute the last residency for a CPU (from entry/exit ticks).
    fn compute_last_residency(&self, cpu: u32) -> u64 {
        let driver = &self.drivers[cpu as usize];
        driver.idle_exit_tick.saturating_sub(driver.idle_entry_tick)
    }
}

impl Default for CpuIdleSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

/// Format CPU idle state information into a buffer.
///
/// Writes a human-readable summary of idle states for the
/// given CPU into `buf`, returning the number of bytes written.
pub fn format_cpu_idle_info(
    subsystem: &CpuIdleSubsystem,
    cpu: u32,
    buf: &mut [u8],
) -> Result<usize> {
    if cpu >= subsystem.cpu_count {
        return Err(Error::InvalidArgument);
    }
    let driver = &subsystem.drivers[cpu as usize];
    let mut pos = 0usize;

    // Write header.
    let header = b"CPU Idle States:\n";
    let copy_len = header.len().min(buf.len() - pos);
    buf[pos..pos + copy_len].copy_from_slice(&header[..copy_len]);
    pos += copy_len;

    for i in 0..driver.state_count as usize {
        if pos >= buf.len() {
            break;
        }
        let state = &driver.states[i];
        // Write state index.
        if pos + 4 <= buf.len() {
            buf[pos] = b'C';
            buf[pos + 1] = b'0' + (i as u8);
            buf[pos + 2] = b':';
            buf[pos + 3] = b' ';
            pos += 4;
        }
        // Write name.
        let name_len = state
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(IDLE_NAME_LEN);
        let copy_len = name_len.min(buf.len() - pos);
        buf[pos..pos + copy_len].copy_from_slice(&state.name[..copy_len]);
        pos += copy_len;

        if pos < buf.len() {
            buf[pos] = b'\n';
            pos += 1;
        }
    }
    Ok(pos)
}
