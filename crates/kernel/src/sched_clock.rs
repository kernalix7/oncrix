// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Scheduler clock source.
//!
//! Provides a monotonic, high-resolution clock for the scheduler to
//! measure time slices, CPU utilization, and scheduling latencies.
//! The scheduler clock may differ from wall-clock time to account
//! for time spent in idle or virtualized environments.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of CPU clock sources.
const MAX_CPU_CLOCKS: usize = 64;

/// Nanoseconds per millisecond.
const NS_PER_MS: u64 = 1_000_000;

/// Nanoseconds per second.
const NS_PER_SEC: u64 = 1_000_000_000;

/// Clock stability threshold in parts per million.
const _STABILITY_THRESHOLD_PPM: u64 = 100;

/// Maximum allowed clock skew between CPUs (nanoseconds).
const MAX_CLOCK_SKEW_NS: u64 = 10 * NS_PER_MS;

// ── Types ────────────────────────────────────────────────────────────

/// Clock source type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockSourceType {
    /// TSC-based clock (x86).
    Tsc,
    /// Generic timer (ARM).
    GenericTimer,
    /// HPET timer.
    Hpet,
    /// Software-based jiffies clock.
    Jiffies,
}

impl Default for ClockSourceType {
    fn default() -> Self {
        Self::Jiffies
    }
}

/// Per-CPU scheduler clock state.
#[derive(Debug, Clone)]
pub struct CpuSchedClock {
    /// CPU identifier.
    cpu_id: u32,
    /// Current clock value in nanoseconds.
    clock_ns: u64,
    /// Clock offset relative to the reference CPU.
    offset_ns: i64,
    /// Whether this CPU's clock is stable.
    stable: bool,
    /// Number of clock reads performed.
    read_count: u64,
    /// Last synchronization timestamp.
    last_sync_ns: u64,
    /// Clock source type for this CPU.
    source: ClockSourceType,
}

impl CpuSchedClock {
    /// Creates a new per-CPU clock state.
    pub const fn new(cpu_id: u32) -> Self {
        Self {
            cpu_id,
            clock_ns: 0,
            offset_ns: 0,
            stable: true,
            read_count: 0,
            last_sync_ns: 0,
            source: ClockSourceType::Jiffies,
        }
    }

    /// Returns the current clock value in nanoseconds.
    pub const fn clock_ns(&self) -> u64 {
        self.clock_ns
    }

    /// Returns whether this CPU clock is considered stable.
    pub const fn is_stable(&self) -> bool {
        self.stable
    }

    /// Returns the CPU identifier.
    pub const fn cpu_id(&self) -> u32 {
        self.cpu_id
    }
}

/// Clock synchronization record between two CPUs.
#[derive(Debug, Clone)]
pub struct ClockSyncRecord {
    /// Source CPU.
    source_cpu: u32,
    /// Target CPU.
    target_cpu: u32,
    /// Measured skew in nanoseconds (signed).
    skew_ns: i64,
    /// Timestamp of the measurement.
    measured_at_ns: u64,
    /// Whether the skew is within acceptable limits.
    within_tolerance: bool,
}

impl ClockSyncRecord {
    /// Creates a new clock sync record.
    pub const fn new(source_cpu: u32, target_cpu: u32, skew_ns: i64) -> Self {
        Self {
            source_cpu,
            target_cpu,
            skew_ns,
            measured_at_ns: 0,
            within_tolerance: skew_ns.unsigned_abs() <= MAX_CLOCK_SKEW_NS,
        }
    }

    /// Returns the measured skew.
    pub const fn skew_ns(&self) -> i64 {
        self.skew_ns
    }

    /// Returns whether the skew is within tolerance.
    pub const fn within_tolerance(&self) -> bool {
        self.within_tolerance
    }
}

/// Scheduler clock statistics.
#[derive(Debug, Clone)]
pub struct SchedClockStats {
    /// Total clock reads across all CPUs.
    pub total_reads: u64,
    /// Total synchronization operations.
    pub total_syncs: u64,
    /// Number of CPUs with stable clocks.
    pub stable_cpus: u32,
    /// Number of CPUs with unstable clocks.
    pub unstable_cpus: u32,
    /// Maximum observed skew in nanoseconds.
    pub max_skew_ns: u64,
}

impl Default for SchedClockStats {
    fn default() -> Self {
        Self::new()
    }
}

impl SchedClockStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_reads: 0,
            total_syncs: 0,
            stable_cpus: 0,
            unstable_cpus: 0,
            max_skew_ns: 0,
        }
    }
}

/// Central scheduler clock manager.
#[derive(Debug)]
pub struct SchedClockManager {
    /// Per-CPU clock states.
    cpu_clocks: [Option<CpuSchedClock>; MAX_CPU_CLOCKS],
    /// Number of registered CPUs.
    cpu_count: usize,
    /// Active clock source type.
    active_source: ClockSourceType,
    /// Whether the global clock is stable.
    global_stable: bool,
    /// Total synchronizations performed.
    total_syncs: u64,
    /// Global epoch counter.
    epoch: u64,
}

impl Default for SchedClockManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SchedClockManager {
    /// Creates a new scheduler clock manager.
    pub const fn new() -> Self {
        Self {
            cpu_clocks: [const { None }; MAX_CPU_CLOCKS],
            cpu_count: 0,
            active_source: ClockSourceType::Jiffies,
            global_stable: true,
            total_syncs: 0,
            epoch: 0,
        }
    }

    /// Registers a CPU with the scheduler clock.
    pub fn register_cpu(&mut self, cpu_id: u32, source: ClockSourceType) -> Result<()> {
        if (cpu_id as usize) >= MAX_CPU_CLOCKS {
            return Err(Error::InvalidArgument);
        }
        if self.cpu_clocks[cpu_id as usize].is_some() {
            return Err(Error::AlreadyExists);
        }
        let mut clock = CpuSchedClock::new(cpu_id);
        clock.source = source;
        self.cpu_clocks[cpu_id as usize] = Some(clock);
        self.cpu_count += 1;
        Ok(())
    }

    /// Reads the scheduler clock for a given CPU.
    pub fn read_clock(&mut self, cpu_id: u32) -> Result<u64> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPU_CLOCKS {
            return Err(Error::InvalidArgument);
        }
        let clock = self.cpu_clocks[idx].as_mut().ok_or(Error::NotFound)?;
        clock.read_count += 1;
        Ok(clock.clock_ns)
    }

    /// Updates the clock value for a CPU.
    pub fn update_clock(&mut self, cpu_id: u32, ns: u64) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPU_CLOCKS {
            return Err(Error::InvalidArgument);
        }
        let clock = self.cpu_clocks[idx].as_mut().ok_or(Error::NotFound)?;
        clock.clock_ns = ns;
        Ok(())
    }

    /// Synchronizes clock between two CPUs, recording skew.
    pub fn sync_clocks(&mut self, source_cpu: u32, target_cpu: u32) -> Result<ClockSyncRecord> {
        let src_idx = source_cpu as usize;
        let tgt_idx = target_cpu as usize;
        if src_idx >= MAX_CPU_CLOCKS || tgt_idx >= MAX_CPU_CLOCKS {
            return Err(Error::InvalidArgument);
        }
        let src_ns = self.cpu_clocks[src_idx]
            .as_ref()
            .ok_or(Error::NotFound)?
            .clock_ns;
        let tgt_ns = self.cpu_clocks[tgt_idx]
            .as_ref()
            .ok_or(Error::NotFound)?
            .clock_ns;
        let skew = (tgt_ns as i64) - (src_ns as i64);
        let record = ClockSyncRecord::new(source_cpu, target_cpu, skew);
        if !record.within_tolerance {
            if let Some(tgt) = &mut self.cpu_clocks[tgt_idx] {
                tgt.stable = false;
            }
            self.global_stable = false;
        }
        self.total_syncs += 1;
        Ok(record)
    }

    /// Sets the global clock source type.
    pub fn set_source(&mut self, source: ClockSourceType) -> Result<()> {
        self.active_source = source;
        self.epoch += 1;
        for clock in self.cpu_clocks.iter_mut().flatten() {
            clock.source = source;
        }
        Ok(())
    }

    /// Marks a CPU clock as stable or unstable.
    pub fn set_cpu_stability(&mut self, cpu_id: u32, stable: bool) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPU_CLOCKS {
            return Err(Error::InvalidArgument);
        }
        let clock = self.cpu_clocks[idx].as_mut().ok_or(Error::NotFound)?;
        clock.stable = stable;
        Ok(())
    }

    /// Returns aggregate statistics.
    pub fn stats(&self) -> SchedClockStats {
        let mut s = SchedClockStats::new();
        s.total_syncs = self.total_syncs;
        for clock in self.cpu_clocks.iter().flatten() {
            s.total_reads += clock.read_count;
            if clock.stable {
                s.stable_cpus += 1;
            } else {
                s.unstable_cpus += 1;
            }
        }
        s
    }

    /// Returns the number of registered CPUs.
    pub const fn cpu_count(&self) -> usize {
        self.cpu_count
    }

    /// Returns whether the global clock is stable.
    pub const fn is_global_stable(&self) -> bool {
        self.global_stable
    }
}
