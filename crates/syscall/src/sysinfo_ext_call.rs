// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sysinfo(2)` syscall handler — extended system information.
//!
//! Returns global system statistics: uptime, memory, swap, load averages,
//! and the number of running processes.  This module extends the basic
//! `sysinfo_call.rs` with load-average computation, memory classification,
//! and a mutable system-state store.
//!
//! # Syscall signature
//!
//! ```text
//! int sysinfo(struct sysinfo *info);
//! ```
//!
//! # POSIX reference
//!
//! `sysinfo` is a Linux extension; not in POSIX.1-2024.
//!
//! # References
//!
//! - Linux: `kernel/sys.c` `sys_sysinfo()`
//! - `sysinfo(2)` man page
//! - `include/uapi/linux/sysinfo.h`

use oncrix_lib::Result;

// ---------------------------------------------------------------------------
// SysInfo — full `struct sysinfo`
// ---------------------------------------------------------------------------

/// Full `struct sysinfo` as returned by the kernel.
///
/// All memory values are in units of `mem_unit` bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SysInfo {
    /// Seconds since boot.
    pub uptime: i64,
    /// 1-minute load average (scaled by `SI_LOAD_SHIFT`).
    pub loads_1: u64,
    /// 5-minute load average.
    pub loads_5: u64,
    /// 15-minute load average.
    pub loads_15: u64,
    /// Total usable main memory.
    pub totalram: u64,
    /// Available memory.
    pub freeram: u64,
    /// Memory used by shared pages.
    pub sharedram: u64,
    /// Memory used by buffers.
    pub bufferram: u64,
    /// Total swap space.
    pub totalswap: u64,
    /// Free swap space.
    pub freeswap: u64,
    /// Number of current processes.
    pub procs: u16,
    /// Padding.
    pub pad: u16,
    /// Padding.
    pub pad2: u32,
    /// Total high memory.
    pub totalhigh: u64,
    /// Available high memory.
    pub freehigh: u64,
    /// Memory unit size in bytes.
    pub mem_unit: u32,
}

/// Shift for load average fixed-point encoding.
pub const SI_LOAD_SHIFT: u32 = 16;

impl Default for SysInfo {
    fn default() -> Self {
        Self {
            uptime: 0,
            loads_1: 0,
            loads_5: 0,
            loads_15: 0,
            totalram: 0,
            freeram: 0,
            sharedram: 0,
            bufferram: 0,
            totalswap: 0,
            freeswap: 0,
            procs: 0,
            pad: 0,
            pad2: 0,
            totalhigh: 0,
            freehigh: 0,
            mem_unit: 1,
        }
    }
}

// ---------------------------------------------------------------------------
// LoadAverage — exponential moving average
// ---------------------------------------------------------------------------

/// Exponential moving average for system load.
///
/// Uses the standard POSIX formula:
/// `load = load * exp_factor + n_running * (1 - exp_factor)`
/// represented as fixed-point integers scaled by `SI_LOAD_SHIFT`.
#[derive(Debug, Clone, Copy, Default)]
pub struct LoadAverage {
    /// Fixed-point load value.
    val: u64,
    /// Decay factor numerator (computed from window constant).
    exp_num: u64,
    /// Decay factor denominator.
    exp_den: u64,
}

impl LoadAverage {
    /// Create with specified exponential decay (num/den <= 1).
    pub const fn new(exp_num: u64, exp_den: u64) -> Self {
        Self {
            val: 0,
            exp_num,
            exp_den,
        }
    }

    /// One-minute load average decay (Linux uses EXP_1 = 1884 / 2048 ≈ e^(-5/60)).
    pub const fn one_min() -> Self {
        Self::new(1884, 2048)
    }
    /// Five-minute load average decay.
    pub const fn five_min() -> Self {
        Self::new(2014, 2048)
    }
    /// Fifteen-minute load average decay.
    pub const fn fifteen_min() -> Self {
        Self::new(2037, 2048)
    }

    /// Update with new sample `n_running` (number of runnable tasks).
    pub fn update(&mut self, n_running: u32) {
        let n = (n_running as u64) << SI_LOAD_SHIFT;
        // load = load * exp_num/exp_den + n * (1 - exp_num/exp_den)
        self.val = (self.val * self.exp_num + n * (self.exp_den - self.exp_num)) / self.exp_den;
    }

    /// Return the current load average scaled by `SI_LOAD_SHIFT`.
    pub const fn scaled(&self) -> u64 {
        self.val
    }
}

// ---------------------------------------------------------------------------
// SystemState — mutable kernel global state
// ---------------------------------------------------------------------------

/// Global system state used to answer `sysinfo` queries.
pub struct SystemState {
    /// Uptime in seconds.
    pub uptime_secs: i64,
    /// Total physical memory pages.
    pub total_pages: u64,
    /// Free physical memory pages.
    pub free_pages: u64,
    /// Shared memory pages.
    pub shared_pages: u64,
    /// Buffer cache pages.
    pub buffer_pages: u64,
    /// Total swap pages.
    pub total_swap_pages: u64,
    /// Free swap pages.
    pub free_swap_pages: u64,
    /// Page size in bytes.
    pub page_size: u32,
    /// Number of processes.
    pub nr_procs: u16,
    /// Load averages.
    pub load_1: LoadAverage,
    pub load_5: LoadAverage,
    pub load_15: LoadAverage,
}

impl SystemState {
    /// Create a default system state (4 GiB total, 2 GiB free, 4 KiB pages).
    pub const fn new() -> Self {
        Self {
            uptime_secs: 0,
            total_pages: 1048576, // 4 GiB / 4 KiB
            free_pages: 524288,   // 2 GiB / 4 KiB
            shared_pages: 0,
            buffer_pages: 0,
            total_swap_pages: 524288, // 2 GiB swap
            free_swap_pages: 524288,
            page_size: 4096,
            nr_procs: 1,
            load_1: LoadAverage::new(1884, 2048),
            load_5: LoadAverage::new(2014, 2048),
            load_15: LoadAverage::new(2037, 2048),
        }
    }

    /// Snapshot the current state as a [`SysInfo`] structure.
    pub fn snapshot(&self) -> SysInfo {
        SysInfo {
            uptime: self.uptime_secs,
            loads_1: self.load_1.scaled(),
            loads_5: self.load_5.scaled(),
            loads_15: self.load_15.scaled(),
            totalram: self.total_pages * self.page_size as u64,
            freeram: self.free_pages * self.page_size as u64,
            sharedram: self.shared_pages * self.page_size as u64,
            bufferram: self.buffer_pages * self.page_size as u64,
            totalswap: self.total_swap_pages * self.page_size as u64,
            freeswap: self.free_swap_pages * self.page_size as u64,
            procs: self.nr_procs,
            pad: 0,
            pad2: 0,
            totalhigh: 0,
            freehigh: 0,
            mem_unit: self.page_size,
        }
    }
}

impl Default for SystemState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// sys_sysinfo — entry point
// ---------------------------------------------------------------------------

/// Handler for `sysinfo(2)`.
///
/// Returns a snapshot of the current system state.
///
/// # Arguments
///
/// * `state` — Reference to the current system state.
///
/// # Returns
///
/// Always succeeds; returns `Ok(SysInfo)`.
pub fn sys_sysinfo(state: &SystemState) -> Result<SysInfo> {
    Ok(state.snapshot())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_sysinfo() {
        let state = SystemState::new();
        let info = sys_sysinfo(&state).unwrap();
        assert_eq!(info.mem_unit, 4096);
        assert!(info.totalram > 0);
        assert!(info.freeram <= info.totalram);
    }

    #[test]
    fn uptime_reflected() {
        let mut state = SystemState::new();
        state.uptime_secs = 3600;
        let info = sys_sysinfo(&state).unwrap();
        assert_eq!(info.uptime, 3600);
    }

    #[test]
    fn procs_reflected() {
        let mut state = SystemState::new();
        state.nr_procs = 42;
        let info = sys_sysinfo(&state).unwrap();
        assert_eq!(info.procs, 42);
    }

    #[test]
    fn load_average_update() {
        let mut load = LoadAverage::one_min();
        load.update(4);
        let scaled = load.scaled();
        // After one sample with 4 running tasks the load should be > 0.
        assert!(scaled > 0);
    }

    #[test]
    fn load_average_decays() {
        let mut load = LoadAverage::one_min();
        load.update(8);
        let high = load.scaled();
        load.update(0);
        let low = load.scaled();
        assert!(low < high);
    }

    #[test]
    fn free_swap_not_exceeds_total() {
        let state = SystemState::new();
        let info = sys_sysinfo(&state).unwrap();
        assert!(info.freeswap <= info.totalswap);
    }
}
