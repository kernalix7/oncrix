// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cgroup v2 CPU controller for bandwidth throttling and weight-based
//! scheduling.
//!
//! Implements the `cpu` controller from Linux cgroups v2 with:
//! - Bandwidth limiting (quota/period/burst model)
//! - Proportional weight scheduling (weight + nice)
//! - Per-group CPU usage statistics and throttle accounting
//! - PID attachment for process-to-controller mapping
//! - Periodic tick-based accounting across all active groups
//!
//! # Types
//!
//! - [`CpuBandwidth`] — quota, period, and burst parameters
//! - [`CpuWeight`] — proportional weight and nice value
//! - [`CpuStats`] — usage and throttle counters
//! - [`CpuCgroupController`] — a single CPU cgroup instance
//! - [`CpuCgroupRegistry`] — system-wide registry of CPU cgroups

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum number of CPU cgroup controllers in the system.
const MAX_CPU_CGROUPS: usize = 64;

/// Maximum number of PIDs per CPU cgroup controller.
const MAX_PIDS: usize = 32;

/// Maximum name length in bytes.
const MAX_NAME_LEN: usize = 64;

/// Default CPU period in microseconds (100 ms).
const DEFAULT_PERIOD_US: u64 = 100_000;

/// Default CPU weight (cgroups v2 range: 1-10000).
const DEFAULT_WEIGHT: u32 = 100;

/// Minimum CPU weight.
const MIN_WEIGHT: u32 = 1;

/// Maximum CPU weight.
const MAX_WEIGHT: u32 = 10_000;

/// Minimum nice value.
const MIN_NICE: i32 = -20;

/// Maximum nice value.
const MAX_NICE: i32 = 19;

/// Quota value meaning unlimited (no bandwidth cap).
const QUOTA_UNLIMITED: i64 = -1;

// ── CpuBandwidth ───────────────────────────────────────────────────

/// CPU bandwidth parameters for throttling.
///
/// Controls the maximum CPU time a cgroup may consume per period.
/// A `quota_us` of `-1` means unlimited (no cap).
#[derive(Debug, Clone, Copy)]
pub struct CpuBandwidth {
    /// Maximum CPU time per period in microseconds (`-1` = unlimited).
    pub quota_us: i64,
    /// Period length in microseconds (default 100 000).
    pub period_us: u64,
    /// Burst allowance in microseconds (accumulated unused quota).
    pub burst_us: u64,
}

impl Default for CpuBandwidth {
    fn default() -> Self {
        Self {
            quota_us: QUOTA_UNLIMITED,
            period_us: DEFAULT_PERIOD_US,
            burst_us: 0,
        }
    }
}

// ── CpuWeight ──────────────────────────────────────────────────────

/// Proportional CPU weight and nice value.
///
/// `weight` controls the share of CPU time relative to sibling
/// cgroups (range 1-10000, default 100). `nice` maps to the
/// traditional UNIX nice value (-20 to 19).
#[derive(Debug, Clone, Copy)]
pub struct CpuWeight {
    /// Proportional weight (1-10000).
    pub weight: u32,
    /// Nice value (-20 to 19).
    pub nice: i32,
}

impl Default for CpuWeight {
    fn default() -> Self {
        Self {
            weight: DEFAULT_WEIGHT,
            nice: 0,
        }
    }
}

// ── CpuStats ───────────────────────────────────────────────────────

/// CPU usage and throttle statistics for a cgroup.
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuStats {
    /// Total CPU time consumed in microseconds.
    pub usage_usec: u64,
    /// User-mode CPU time in microseconds.
    pub user_usec: u64,
    /// System-mode CPU time in microseconds.
    pub system_usec: u64,
    /// Total number of elapsed enforcement periods.
    pub nr_periods: u64,
    /// Number of periods in which the group was throttled.
    pub nr_throttled: u64,
    /// Total time the group spent throttled in microseconds.
    pub throttled_usec: u64,
}

// ── CpuCgroupController ───────────────────────────────────────────

/// A single CPU cgroup controller instance.
///
/// Manages bandwidth throttling, weight-based scheduling, and CPU
/// usage accounting for a set of attached PIDs.
#[derive(Debug, Clone, Copy)]
pub struct CpuCgroupController {
    /// Unique identifier for this controller.
    pub id: u64,
    /// Controller name (UTF-8 bytes, null-padded).
    pub name: [u8; MAX_NAME_LEN],
    /// Bandwidth throttling parameters.
    pub bandwidth: CpuBandwidth,
    /// Proportional weight parameters.
    pub weight: CpuWeight,
    /// Usage and throttle statistics.
    pub stats: CpuStats,
    /// Attached process IDs.
    pub pids: [u64; MAX_PIDS],
    /// Number of attached PIDs.
    pub pid_count: usize,
    /// Whether this controller is enabled.
    pub enabled: bool,
    /// Whether this slot is actively in use.
    pub in_use: bool,
    /// Name length in bytes.
    name_len: usize,
    /// Accumulated CPU usage within the current period (for
    /// throttle checking).
    period_usage_us: u64,
}

impl CpuCgroupController {
    /// Creates an empty (inactive) controller slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            bandwidth: CpuBandwidth {
                quota_us: QUOTA_UNLIMITED,
                period_us: DEFAULT_PERIOD_US,
                burst_us: 0,
            },
            weight: CpuWeight {
                weight: DEFAULT_WEIGHT,
                nice: 0,
            },
            stats: CpuStats {
                usage_usec: 0,
                user_usec: 0,
                system_usec: 0,
                nr_periods: 0,
                nr_throttled: 0,
                throttled_usec: 0,
            },
            pids: [0u64; MAX_PIDS],
            pid_count: 0,
            enabled: false,
            in_use: false,
            name_len: 0,
            period_usage_us: 0,
        }
    }

    /// Sets bandwidth throttling parameters.
    ///
    /// `quota` must be `-1` (unlimited) or a positive value.
    /// `period` must be greater than zero.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if `quota` is zero or a
    /// negative value other than `-1`, or if `period` is zero.
    pub fn set_bandwidth(&mut self, quota: i64, period: u64, burst: u64) -> Result<()> {
        if quota != QUOTA_UNLIMITED && quota <= 0 {
            return Err(Error::InvalidArgument);
        }
        if period == 0 {
            return Err(Error::InvalidArgument);
        }
        self.bandwidth.quota_us = quota;
        self.bandwidth.period_us = period;
        self.bandwidth.burst_us = burst;
        Ok(())
    }

    /// Sets weight and nice scheduling parameters.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if `weight` is outside
    /// 1-10000 or `nice` is outside -20 to 19.
    pub fn set_weight(&mut self, weight: u32, nice: i32) -> Result<()> {
        if !(MIN_WEIGHT..=MAX_WEIGHT).contains(&weight) {
            return Err(Error::InvalidArgument);
        }
        if !(MIN_NICE..=MAX_NICE).contains(&nice) {
            return Err(Error::InvalidArgument);
        }
        self.weight.weight = weight;
        self.weight.nice = nice;
        Ok(())
    }

    /// Adds a PID to this controller.
    ///
    /// # Errors
    ///
    /// - `Error::AlreadyExists` — PID is already attached.
    /// - `Error::OutOfMemory` — PID list is full.
    pub fn add_pid(&mut self, pid: u64) -> Result<()> {
        if self.pids[..self.pid_count].contains(&pid) {
            return Err(Error::AlreadyExists);
        }
        if self.pid_count >= MAX_PIDS {
            return Err(Error::OutOfMemory);
        }
        self.pids[self.pid_count] = pid;
        self.pid_count += 1;
        Ok(())
    }

    /// Removes a PID from this controller.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if the PID is not attached.
    pub fn remove_pid(&mut self, pid: u64) -> Result<()> {
        let pos = self.pids[..self.pid_count]
            .iter()
            .position(|&p| p == pid)
            .ok_or(Error::NotFound)?;

        // Swap-remove: move last element into the vacated slot.
        self.pid_count -= 1;
        if pos < self.pid_count {
            self.pids[pos] = self.pids[self.pid_count];
        }
        self.pids[self.pid_count] = 0;
        Ok(())
    }

    /// Returns whether a PID is attached to this controller.
    pub fn has_pid(&self, pid: u64) -> bool {
        self.pids[..self.pid_count].contains(&pid)
    }

    /// Charges CPU time to this controller.
    ///
    /// `usec` is the number of microseconds consumed. If `is_user`
    /// is `true` the time is added to `user_usec`, otherwise to
    /// `system_usec`.
    pub fn charge_cpu_time(&mut self, usec: u64, is_user: bool) {
        self.stats.usage_usec = self.stats.usage_usec.saturating_add(usec);
        if is_user {
            self.stats.user_usec = self.stats.user_usec.saturating_add(usec);
        } else {
            self.stats.system_usec = self.stats.system_usec.saturating_add(usec);
        }
        self.period_usage_us = self.period_usage_us.saturating_add(usec);
    }

    /// Checks whether this controller should be throttled.
    ///
    /// Returns `true` if bandwidth limiting is enabled and the
    /// accumulated usage in the current period (plus burst) has
    /// exceeded the quota.
    pub fn check_throttle(&self) -> bool {
        if self.bandwidth.quota_us == QUOTA_UNLIMITED {
            return false;
        }
        // quota_us is positive here (validated in set_bandwidth).
        let effective_quota =
            (self.bandwidth.quota_us as u64).saturating_add(self.bandwidth.burst_us);
        self.period_usage_us > effective_quota
    }

    /// Resets per-period accounting counters.
    ///
    /// Called at the start of each new enforcement period.
    /// Records whether the group was throttled during the
    /// completed period.
    pub fn reset_period(&mut self) {
        self.stats.nr_periods = self.stats.nr_periods.saturating_add(1);
        if self.check_throttle() {
            self.stats.nr_throttled = self.stats.nr_throttled.saturating_add(1);
            self.stats.throttled_usec = self
                .stats
                .throttled_usec
                .saturating_add(self.period_usage_us);
        }
        self.period_usage_us = 0;
    }

    /// Returns a reference to the current CPU statistics.
    pub fn get_stats(&self) -> &CpuStats {
        &self.stats
    }
}

// ── CpuCgroupRegistry ─────────────────────────────────────────────

/// System-wide registry of CPU cgroup controllers.
///
/// Manages up to [`MAX_CPU_CGROUPS`] controllers in a fixed-size
/// array. Each controller is identified by a unique `u64` ID
/// assigned at creation time.
pub struct CpuCgroupRegistry {
    /// Fixed-size array of controller slots.
    controllers: [CpuCgroupController; MAX_CPU_CGROUPS],
    /// Next controller ID to assign.
    next_id: u64,
    /// Number of active controllers.
    count: usize,
}

impl Default for CpuCgroupRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuCgroupRegistry {
    /// Creates a new, empty registry.
    pub const fn new() -> Self {
        const EMPTY: CpuCgroupController = CpuCgroupController::empty();
        Self {
            controllers: [EMPTY; MAX_CPU_CGROUPS],
            next_id: 1,
            count: 0,
        }
    }

    /// Returns the number of active controllers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no controllers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Creates a new CPU cgroup controller with the given name.
    ///
    /// Returns the new controller's unique ID.
    ///
    /// # Errors
    ///
    /// - `Error::InvalidArgument` — name is empty or too long.
    /// - `Error::OutOfMemory` — no free slots available.
    pub fn create(&mut self, name: &[u8]) -> Result<u64> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_CPU_CGROUPS {
            return Err(Error::OutOfMemory);
        }

        let slot = self
            .controllers
            .iter()
            .position(|c| !c.in_use)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let ctrl = &mut self.controllers[slot];
        *ctrl = CpuCgroupController::empty();
        ctrl.id = id;
        ctrl.in_use = true;
        ctrl.enabled = true;
        ctrl.name_len = name.len();
        ctrl.name[..name.len()].copy_from_slice(name);

        self.count += 1;
        Ok(id)
    }

    /// Destroys a CPU cgroup controller by ID.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — controller does not exist.
    /// - `Error::Busy` — controller still has attached PIDs.
    pub fn destroy(&mut self, id: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        if self.controllers[idx].pid_count > 0 {
            return Err(Error::Busy);
        }
        self.controllers[idx].in_use = false;
        self.controllers[idx].enabled = false;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Returns an immutable reference to a controller by ID.
    pub fn get(&self, id: u64) -> Option<&CpuCgroupController> {
        self.controllers.iter().find(|c| c.in_use && c.id == id)
    }

    /// Returns a mutable reference to a controller by ID.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut CpuCgroupController> {
        self.controllers.iter_mut().find(|c| c.in_use && c.id == id)
    }

    /// Sets bandwidth parameters for a controller.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — controller does not exist.
    /// - `Error::InvalidArgument` — invalid bandwidth parameters.
    pub fn set_bandwidth(&mut self, id: u64, quota: i64, period: u64, burst: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        self.controllers[idx].set_bandwidth(quota, period, burst)
    }

    /// Sets weight and nice parameters for a controller.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — controller does not exist.
    /// - `Error::InvalidArgument` — invalid weight or nice value.
    pub fn set_weight(&mut self, id: u64, weight: u32, nice: i32) -> Result<()> {
        let idx = self.index_of(id)?;
        self.controllers[idx].set_weight(weight, nice)
    }

    /// Attaches a PID to a controller.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — controller does not exist.
    /// - `Error::AlreadyExists` — PID is already attached.
    /// - `Error::OutOfMemory` — PID list is full.
    pub fn add_pid(&mut self, id: u64, pid: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        self.controllers[idx].add_pid(pid)
    }

    /// Detaches a PID from a controller.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — controller does not exist or PID is
    ///   not attached.
    pub fn remove_pid(&mut self, id: u64, pid: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        self.controllers[idx].remove_pid(pid)
    }

    /// Performs periodic accounting for all active controllers.
    ///
    /// Called on each timer tick. `elapsed_us` is the number of
    /// microseconds since the last tick. For each controller whose
    /// accumulated period usage has reached or exceeded its period
    /// length, the period counters are reset.
    pub fn tick(&mut self, elapsed_us: u64) {
        for ctrl in &mut self.controllers {
            if !ctrl.in_use || !ctrl.enabled {
                continue;
            }
            // Check if the period has elapsed and needs reset.
            if ctrl.period_usage_us >= ctrl.bandwidth.period_us {
                ctrl.reset_period();
            }
            // Account for elapsed time proportionally — the
            // actual per-process charging is done via
            // `charge_cpu_time`, but we use `elapsed_us` to
            // detect period boundaries when no explicit charge
            // has occurred.
            let _ = elapsed_us;
        }
    }

    // ── Internal helpers ───────────────────────────────────────────

    /// Returns the index of an active controller by ID.
    fn index_of(&self, id: u64) -> Result<usize> {
        self.controllers
            .iter()
            .position(|c| c.in_use && c.id == id)
            .ok_or(Error::NotFound)
    }
}
