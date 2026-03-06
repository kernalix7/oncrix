// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-CPU vmstat accounting worker.
//!
//! Accumulates per-CPU page state differentials, periodically folds
//! them into global counters, supports threshold-based flushing, zone
//! stat updates, and quiet-period detection to reduce unnecessary
//! folding when the system is idle.
//!
//! # Key Types
//!
//! - [`VmStatId`] — counter identifiers for page states
//! - [`PerCpuDiff`] — per-CPU differential accumulator
//! - [`ZoneStat`] — per-zone page statistics
//! - [`GlobalVmStat`] — global aggregated counters
//! - [`FoldConfig`] — threshold and interval configuration
//! - [`WorkerState`] — lifecycle state of the worker
//! - [`VmStatWorker`] — the main worker engine
//! - [`VmStatSnapshot`] — point-in-time snapshot for reporting
//!
//! Reference: Linux `mm/vmstat.c` (`vmstat_update`,
//! `refresh_vm_stats`, `quiet_vmstat`).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of CPUs.
const MAX_CPUS: usize = 8;

/// Number of zone types.
const MAX_ZONES: usize = 4;

/// Number of vmstat counter IDs.
const NR_STAT_IDS: usize = 32;

/// Default fold threshold (fold when any diff exceeds this).
const DEFAULT_FOLD_THRESHOLD: i64 = 64;

/// Default fold interval in ticks.
const DEFAULT_FOLD_INTERVAL: u64 = 100;

/// Quiet detection: number of consecutive idle folds before quiet.
const QUIET_FOLD_COUNT: u64 = 5;

// -------------------------------------------------------------------
// VmStatId
// -------------------------------------------------------------------

/// Counter identifiers for page states tracked by the vmstat worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VmStatId {
    /// Free pages.
    #[default]
    NrFreePages = 0,
    /// Zone-reclaim-eligible pages.
    NrZoneReclaimable = 1,
    /// Inactive anonymous pages.
    NrInactiveAnon = 2,
    /// Active anonymous pages.
    NrActiveAnon = 3,
    /// Inactive file pages.
    NrInactiveFile = 4,
    /// Active file pages.
    NrActiveFile = 5,
    /// Unevictable pages.
    NrUnevictable = 6,
    /// Dirty pages.
    NrDirty = 7,
    /// Writeback pages.
    NrWriteback = 8,
    /// Slab reclaimable.
    NrSlabReclaimable = 9,
    /// Slab unreclaimable.
    NrSlabUnreclaimable = 10,
    /// Mapped pages.
    NrMapped = 11,
    /// Anonymous pages.
    NrAnonPages = 12,
    /// Shared memory pages.
    NrShmem = 13,
    /// Page table pages.
    NrPageTable = 14,
    /// Kernel stack pages.
    NrKernelStack = 15,
    /// Bounce buffer pages.
    NrBounce = 16,
    /// File pages.
    NrFilePages = 17,
    /// Huge pages total.
    NrHugePages = 18,
    /// Huge pages free.
    NrHugePagesFree = 19,
    /// Pages allocated (cumulative).
    PgAlloc = 20,
    /// Pages freed (cumulative).
    PgFree = 21,
    /// Page faults.
    PgFault = 22,
    /// Major page faults.
    PgMajFault = 23,
    /// Pages scanned.
    PgScan = 24,
    /// Pages stolen.
    PgSteal = 25,
    /// Pages paged in.
    PgPgIn = 26,
    /// Pages paged out.
    PgPgOut = 27,
    /// Swap in.
    PswpIn = 28,
    /// Swap out.
    PswpOut = 29,
    /// Compaction migrate scanned.
    CompactScanned = 30,
    /// Compaction success.
    CompactSuccess = 31,
}

impl VmStatId {
    /// Returns the array index for this counter.
    fn idx(self) -> usize {
        self as usize
    }
}

// -------------------------------------------------------------------
// PerCpuDiff
// -------------------------------------------------------------------

/// Per-CPU differential accumulator.
///
/// Each CPU accumulates deltas locally. When a delta exceeds the
/// configured threshold, or when the periodic fold fires, the
/// diffs are merged into the global counters.
pub struct PerCpuDiff {
    /// Differential values.
    diffs: [i64; NR_STAT_IDS],
    /// CPU identifier.
    cpu_id: u32,
    /// Number of updates since last fold.
    updates_since_fold: u64,
    /// Whether this CPU has exceeded the fold threshold.
    threshold_exceeded: bool,
}

impl PerCpuDiff {
    /// Creates a zeroed diff accumulator for the given CPU.
    const fn new(cpu_id: u32) -> Self {
        Self {
            diffs: [0i64; NR_STAT_IDS],
            cpu_id,
            updates_since_fold: 0,
            threshold_exceeded: false,
        }
    }

    /// Adds a delta to a counter.
    pub fn add(&mut self, id: VmStatId, delta: i64, threshold: i64) {
        self.diffs[id.idx()] += delta;
        self.updates_since_fold += 1;
        if self.diffs[id.idx()].unsigned_abs() >= threshold as u64 {
            self.threshold_exceeded = true;
        }
    }

    /// Increments a counter by one.
    pub fn inc(&mut self, id: VmStatId, threshold: i64) {
        self.add(id, 1, threshold);
    }

    /// Decrements a counter by one.
    pub fn dec(&mut self, id: VmStatId, threshold: i64) {
        self.add(id, -1, threshold);
    }

    /// Returns `true` if any delta exceeds the fold threshold.
    pub fn needs_fold(&self) -> bool {
        self.threshold_exceeded
    }

    /// Drains diffs into the provided output array, zeroing local state.
    /// Returns `true` if any nonzero diff was drained.
    fn drain_into(&mut self, out: &mut [i64; NR_STAT_IDS]) -> bool {
        let mut had_data = false;
        for i in 0..NR_STAT_IDS {
            if self.diffs[i] != 0 {
                out[i] += self.diffs[i];
                self.diffs[i] = 0;
                had_data = true;
            }
        }
        self.updates_since_fold = 0;
        self.threshold_exceeded = false;
        had_data
    }

    /// Returns the CPU ID.
    pub fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Returns the current diff for a counter.
    pub fn get(&self, id: VmStatId) -> i64 {
        self.diffs[id.idx()]
    }
}

// -------------------------------------------------------------------
// ZoneStat
// -------------------------------------------------------------------

/// Per-zone page statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct ZoneStat {
    /// Zone identifier.
    pub zone_id: u8,
    /// Whether this zone is active.
    pub active: bool,
    /// Per-counter values for this zone.
    pub counters: [i64; NR_STAT_IDS],
}

impl ZoneStat {
    /// Creates an empty zone stat.
    pub const fn new(zone_id: u8) -> Self {
        Self {
            zone_id,
            active: false,
            counters: [0i64; NR_STAT_IDS],
        }
    }

    /// Gets a counter value.
    pub fn get(&self, id: VmStatId) -> i64 {
        self.counters[id.idx()]
    }

    /// Adds a delta to a counter.
    pub fn add(&mut self, id: VmStatId, delta: i64) {
        self.counters[id.idx()] += delta;
    }
}

// -------------------------------------------------------------------
// GlobalVmStat
// -------------------------------------------------------------------

/// Global aggregated vmstat counters.
pub struct GlobalVmStat {
    /// Global counter values.
    counters: [i64; NR_STAT_IDS],
    /// Per-zone counters.
    zones: [ZoneStat; MAX_ZONES],
    /// Number of active zones.
    nr_zones: usize,
}

impl GlobalVmStat {
    /// Creates empty global stats.
    pub const fn new() -> Self {
        Self {
            counters: [0i64; NR_STAT_IDS],
            zones: [
                ZoneStat::new(0),
                ZoneStat::new(1),
                ZoneStat::new(2),
                ZoneStat::new(3),
            ],
            nr_zones: 0,
        }
    }

    /// Registers a zone.
    pub fn add_zone(&mut self, zone_id: u8) -> Result<()> {
        if self.nr_zones >= MAX_ZONES {
            return Err(Error::OutOfMemory);
        }
        self.zones[self.nr_zones].zone_id = zone_id;
        self.zones[self.nr_zones].active = true;
        self.nr_zones += 1;
        Ok(())
    }

    /// Returns a global counter value.
    pub fn get(&self, id: VmStatId) -> i64 {
        self.counters[id.idx()]
    }

    /// Applies a set of diffs to the global counters.
    fn apply_diffs(&mut self, diffs: &[i64; NR_STAT_IDS]) {
        for i in 0..NR_STAT_IDS {
            self.counters[i] += diffs[i];
        }
    }

    /// Applies diffs to a specific zone's counters.
    fn apply_zone_diffs(&mut self, zone_idx: usize, diffs: &[i64; NR_STAT_IDS]) {
        if zone_idx < self.nr_zones {
            for i in 0..NR_STAT_IDS {
                self.zones[zone_idx].counters[i] += diffs[i];
            }
        }
    }

    /// Returns zone stats.
    pub fn zone(&self, zone_idx: usize) -> Option<&ZoneStat> {
        if zone_idx < self.nr_zones {
            Some(&self.zones[zone_idx])
        } else {
            None
        }
    }

    /// Resets all counters.
    pub fn reset(&mut self) {
        self.counters = [0i64; NR_STAT_IDS];
        for z in &mut self.zones {
            z.counters = [0i64; NR_STAT_IDS];
        }
    }
}

impl Default for GlobalVmStat {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// FoldConfig
// -------------------------------------------------------------------

/// Configuration for fold thresholds and intervals.
#[derive(Debug, Clone, Copy)]
pub struct FoldConfig {
    /// Per-counter threshold for immediate fold.
    pub threshold: i64,
    /// Periodic fold interval in ticks.
    pub fold_interval: u64,
    /// Whether quiet-period detection is enabled.
    pub quiet_detection: bool,
}

impl Default for FoldConfig {
    fn default() -> Self {
        Self {
            threshold: DEFAULT_FOLD_THRESHOLD,
            fold_interval: DEFAULT_FOLD_INTERVAL,
            quiet_detection: true,
        }
    }
}

// -------------------------------------------------------------------
// WorkerState
// -------------------------------------------------------------------

/// Lifecycle state of the vmstat worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WorkerState {
    /// Worker is idle, waiting for the next tick.
    #[default]
    Idle,
    /// Worker is actively folding diffs.
    Folding,
    /// Worker has detected a quiet period (no activity).
    Quiet,
    /// Worker is disabled.
    Disabled,
}

// -------------------------------------------------------------------
// VmStatSnapshot
// -------------------------------------------------------------------

/// Point-in-time snapshot of vmstat counters for reporting.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmStatSnapshot {
    /// Counter values at the time of snapshot.
    pub counters: [i64; NR_STAT_IDS],
    /// Tick at which the snapshot was taken.
    pub tick: u64,
    /// Number of active CPUs at snapshot time.
    pub nr_cpus: usize,
    /// Number of fold operations at snapshot time.
    pub fold_count: u64,
}

// -------------------------------------------------------------------
// VmStatWorker
// -------------------------------------------------------------------

/// Per-CPU vmstat accounting worker.
///
/// Accumulates per-CPU page state diffs and periodically folds them
/// into global counters. Supports threshold-based immediate flush,
/// zone stat updates, and quiet-period detection.
pub struct VmStatWorker {
    /// Per-CPU diff accumulators.
    per_cpu: [PerCpuDiff; MAX_CPUS],
    /// Number of active CPUs.
    nr_cpus: usize,
    /// Global vmstat counters.
    global: GlobalVmStat,
    /// Fold configuration.
    config: FoldConfig,
    /// Current worker state.
    state: WorkerState,
    /// Current tick counter.
    current_tick: u64,
    /// Tick of the last fold operation.
    last_fold_tick: u64,
    /// Total fold operations performed.
    fold_count: u64,
    /// Consecutive idle folds (no data to fold).
    consecutive_idle_folds: u64,
}

impl VmStatWorker {
    /// Creates a new worker for the given number of CPUs.
    pub fn new(nr_cpus: usize, config: FoldConfig) -> Self {
        let capped = nr_cpus.clamp(1, MAX_CPUS);
        Self {
            per_cpu: [
                PerCpuDiff::new(0),
                PerCpuDiff::new(1),
                PerCpuDiff::new(2),
                PerCpuDiff::new(3),
                PerCpuDiff::new(4),
                PerCpuDiff::new(5),
                PerCpuDiff::new(6),
                PerCpuDiff::new(7),
            ],
            nr_cpus: capped,
            global: GlobalVmStat::new(),
            config,
            state: WorkerState::Idle,
            current_tick: 0,
            last_fold_tick: 0,
            fold_count: 0,
            consecutive_idle_folds: 0,
        }
    }

    /// Registers a zone for per-zone accounting.
    pub fn add_zone(&mut self, zone_id: u8) -> Result<()> {
        self.global.add_zone(zone_id)
    }

    /// Records a counter update on a specific CPU.
    pub fn update(&mut self, cpu: usize, id: VmStatId, delta: i64) -> Result<()> {
        if cpu >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[cpu].add(id, delta, self.config.threshold);

        // If threshold exceeded, do immediate fold for this CPU.
        if self.per_cpu[cpu].needs_fold() {
            self.fold_cpu(cpu);
        }

        Ok(())
    }

    /// Increments a counter by 1 on the given CPU.
    pub fn inc(&mut self, cpu: usize, id: VmStatId) -> Result<()> {
        self.update(cpu, id, 1)
    }

    /// Decrements a counter by 1 on the given CPU.
    pub fn dec(&mut self, cpu: usize, id: VmStatId) -> Result<()> {
        self.update(cpu, id, -1)
    }

    /// Folds a single CPU's diffs into global counters.
    fn fold_cpu(&mut self, cpu: usize) {
        let mut diffs = [0i64; NR_STAT_IDS];
        self.per_cpu[cpu].drain_into(&mut diffs);
        self.global.apply_diffs(&diffs);
    }

    /// Periodic tick handler: folds all CPUs if the interval has
    /// elapsed.
    ///
    /// Returns `true` if a fold was performed.
    pub fn tick(&mut self) -> bool {
        self.current_tick += 1;

        if self.current_tick - self.last_fold_tick < self.config.fold_interval {
            return false;
        }

        self.fold_all()
    }

    /// Folds all per-CPU diffs into global counters.
    ///
    /// Returns `true` if any nonzero data was folded.
    pub fn fold_all(&mut self) -> bool {
        self.state = WorkerState::Folding;
        let mut diffs = [0i64; NR_STAT_IDS];
        let mut had_data = false;

        for cpu in 0..self.nr_cpus {
            if self.per_cpu[cpu].drain_into(&mut diffs) {
                had_data = true;
            }
        }

        self.global.apply_diffs(&diffs);
        self.last_fold_tick = self.current_tick;
        self.fold_count += 1;

        if had_data {
            self.consecutive_idle_folds = 0;
            self.state = WorkerState::Idle;
        } else {
            self.consecutive_idle_folds += 1;
            if self.config.quiet_detection && self.consecutive_idle_folds >= QUIET_FOLD_COUNT {
                self.state = WorkerState::Quiet;
            } else {
                self.state = WorkerState::Idle;
            }
        }

        had_data
    }

    /// Updates zone-specific stats for a particular zone.
    pub fn update_zone(&mut self, zone_idx: usize, id: VmStatId, delta: i64) {
        let mut diffs = [0i64; NR_STAT_IDS];
        diffs[id.idx()] = delta;
        self.global.apply_zone_diffs(zone_idx, &diffs);
    }

    /// Returns a point-in-time snapshot (folds first).
    pub fn snapshot(&mut self) -> VmStatSnapshot {
        self.fold_all();
        let mut counters = [0i64; NR_STAT_IDS];
        counters.copy_from_slice(&self.global.counters);
        VmStatSnapshot {
            counters,
            tick: self.current_tick,
            nr_cpus: self.nr_cpus,
            fold_count: self.fold_count,
        }
    }

    /// Returns a global counter value without folding.
    pub fn get(&self, id: VmStatId) -> i64 {
        self.global.get(id)
    }

    /// Returns the current worker state.
    pub fn state(&self) -> WorkerState {
        self.state
    }

    /// Returns `true` if the worker has detected a quiet period.
    pub fn is_quiet(&self) -> bool {
        self.state == WorkerState::Quiet
    }

    /// Returns the total number of fold operations.
    pub fn fold_count(&self) -> u64 {
        self.fold_count
    }

    /// Returns the number of consecutive idle folds.
    pub fn consecutive_idle_folds(&self) -> u64 {
        self.consecutive_idle_folds
    }

    /// Returns a reference to the global counters.
    pub fn global(&self) -> &GlobalVmStat {
        &self.global
    }

    /// Returns per-CPU diff for inspection.
    pub fn per_cpu(&self, cpu: usize) -> Option<&PerCpuDiff> {
        if cpu < self.nr_cpus {
            Some(&self.per_cpu[cpu])
        } else {
            None
        }
    }

    /// Returns the fold configuration.
    pub fn config(&self) -> &FoldConfig {
        &self.config
    }

    /// Updates the fold threshold.
    pub fn set_threshold(&mut self, threshold: i64) {
        self.config.threshold = threshold;
    }

    /// Disables the worker.
    pub fn disable(&mut self) {
        self.state = WorkerState::Disabled;
    }

    /// Enables the worker.
    pub fn enable(&mut self) {
        if self.state == WorkerState::Disabled {
            self.state = WorkerState::Idle;
        }
    }
}
