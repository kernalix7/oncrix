// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Periodic vmstat statistics collector.
//!
//! Implements per-CPU differential counters that are periodically
//! folded into per-zone and global aggregates, following the Linux
//! `mm/vmstat.c` design. This allows high-frequency counter updates
//! on hot paths (page allocation, reclaim) without contending on a
//! global lock — each CPU writes to its local [`PerCpuVmstat`] and a
//! periodic [`VmstatCollector::tick`] folds the diffs into zone and
//! global counters.
//!
//! Reference: `.kernelORG/` — `mm/vmstat.c`, `include/linux/vmstat.h`.

use oncrix_lib::{Error, Result};

/// Maximum number of CPUs tracked.
const MAX_CPUS: usize = 8;

/// Maximum number of memory zones tracked.
const MAX_ZONES: usize = 4;

/// Total number of vmstat counter types.
const NUM_COUNTERS: usize = 21;

/// Vmstat counter identifiers.
///
/// Each variant maps to an index in the per-CPU, per-zone, and global
/// counter arrays. The ordering matches Linux's `enum zone_stat_item`
/// for familiarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VmstatCounter {
    /// Number of free pages.
    #[default]
    NrFreePages = 0,
    /// Active anonymous pages (heap/stack, recently accessed).
    NrActiveAnon = 1,
    /// Inactive anonymous pages (candidates for swap-out).
    NrInactiveAnon = 2,
    /// Active file-backed pages (recently accessed page cache).
    NrActiveFile = 3,
    /// Inactive file-backed pages (candidates for reclaim).
    NrInactiveFile = 4,
    /// Unevictable pages (locked, `mlock`ed, ramfs).
    NrUnevictable = 5,
    /// Pages locked via `mlock`.
    NrMlocked = 6,
    /// Dirty pages (modified, not yet written back).
    NrDirty = 7,
    /// Pages under writeback to disk.
    NrWriteback = 8,
    /// Pages used by slab allocators.
    NrSlab = 9,
    /// Pages used for page table structures.
    NrPageTablePages = 10,
    /// Pages used for kernel thread stacks.
    NrKernelStack = 11,
    /// Bounce buffer pages (for DMA to high memory).
    NrBounce = 12,
    /// Pages used by zsmalloc (compressed memory).
    NrZspages = 13,
    /// Free CMA (Contiguous Memory Allocator) pages.
    NrFreeCma = 14,
    /// NUMA allocation hit (allocated on preferred node).
    NumaHit = 15,
    /// NUMA allocation miss (preferred node exhausted).
    NumaMiss = 16,
    /// NUMA foreign allocation (allocated for a remote node).
    NumaForeign = 17,
    /// NUMA interleaved allocation.
    NumaInterleave = 18,
    /// NUMA local allocation (allocated on the local node).
    NumaLocal = 19,
    /// NUMA other-node allocation.
    NumaOther = 20,
}

impl VmstatCounter {
    /// Returns the counter's index as `usize`.
    pub const fn as_usize(self) -> usize {
        self as usize
    }

    /// Returns the total number of counter variants.
    pub const fn count() -> usize {
        NUM_COUNTERS
    }
}

/// Per-CPU differential vmstat counters.
///
/// Each CPU maintains a local set of signed counters that accumulate
/// deltas between fold operations. The `dirty` flag indicates that at
/// least one counter has been modified since the last fold.
#[derive(Debug, Clone)]
pub struct PerCpuVmstat {
    /// Signed differential counters (deltas since last fold).
    counters: [i64; NUM_COUNTERS],
    /// CPU identifier.
    pub cpu_id: u32,
    /// Whether any counter has been modified since the last fold.
    dirty: bool,
}

impl Default for PerCpuVmstat {
    fn default() -> Self {
        Self {
            counters: [0i64; NUM_COUNTERS],
            cpu_id: 0,
            dirty: false,
        }
    }
}

impl PerCpuVmstat {
    /// Creates a new per-CPU vmstat for the given CPU.
    pub const fn new(cpu_id: u32) -> Self {
        Self {
            counters: [0i64; NUM_COUNTERS],
            cpu_id,
            dirty: false,
        }
    }

    /// Increment a counter by 1.
    pub fn inc(&mut self, counter: VmstatCounter) {
        self.counters[counter.as_usize()] += 1;
        self.dirty = true;
    }

    /// Decrement a counter by 1.
    pub fn dec(&mut self, counter: VmstatCounter) {
        self.counters[counter.as_usize()] -= 1;
        self.dirty = true;
    }

    /// Add a value to a counter.
    pub fn add(&mut self, counter: VmstatCounter, val: i64) {
        self.counters[counter.as_usize()] += val;
        self.dirty = true;
    }

    /// Subtract a value from a counter.
    pub fn sub(&mut self, counter: VmstatCounter, val: i64) {
        self.counters[counter.as_usize()] -= val;
        self.dirty = true;
    }

    /// Read the current differential value of a counter.
    pub fn get(&self, counter: VmstatCounter) -> i64 {
        self.counters[counter.as_usize()]
    }

    /// Clear the dirty flag (called after folding).
    pub fn reset_dirty(&mut self) {
        self.dirty = false;
    }
}

/// Per-zone aggregated vmstat counters.
///
/// Accumulates absolute counter values for a single memory zone,
/// along with low/high watermarks that trigger reclaim or throttling.
#[derive(Debug, Clone)]
pub struct ZoneVmstat {
    /// Absolute counter values for this zone.
    counters: [u64; NUM_COUNTERS],
    /// Zone identifier.
    pub zone_id: u32,
    /// Low watermark thresholds per counter.
    low_watermark: [u64; NUM_COUNTERS],
    /// High watermark thresholds per counter.
    high_watermark: [u64; NUM_COUNTERS],
}

impl Default for ZoneVmstat {
    fn default() -> Self {
        Self {
            counters: [0u64; NUM_COUNTERS],
            zone_id: 0,
            low_watermark: [0u64; NUM_COUNTERS],
            high_watermark: [u64::MAX; NUM_COUNTERS],
        }
    }
}

impl ZoneVmstat {
    /// Creates a new per-zone vmstat for the given zone.
    pub const fn new(zone_id: u32) -> Self {
        Self {
            counters: [0u64; NUM_COUNTERS],
            zone_id,
            low_watermark: [0u64; NUM_COUNTERS],
            high_watermark: [u64::MAX; NUM_COUNTERS],
        }
    }

    /// Update a counter by a signed delta.
    ///
    /// Positive values increase the counter, negative values decrease
    /// it. The counter is clamped to zero on underflow.
    pub fn update(&mut self, counter: VmstatCounter, val: i64) {
        let idx = counter.as_usize();
        if val >= 0 {
            self.counters[idx] = self.counters[idx].saturating_add(val as u64);
        } else {
            self.counters[idx] = self.counters[idx].saturating_sub(val.unsigned_abs());
        }
    }

    /// Read the current value of a counter.
    pub fn get(&self, counter: VmstatCounter) -> u64 {
        self.counters[counter.as_usize()]
    }

    /// Check whether a counter is at or below its low watermark.
    pub fn is_low(&self, counter: VmstatCounter) -> bool {
        let idx = counter.as_usize();
        self.counters[idx] <= self.low_watermark[idx]
    }

    /// Check whether a counter is at or above its high watermark.
    pub fn is_high(&self, counter: VmstatCounter) -> bool {
        let idx = counter.as_usize();
        self.counters[idx] >= self.high_watermark[idx]
    }
}

/// Vmstat periodic statistics collector.
///
/// Aggregates per-CPU differential counters into per-zone and global
/// statistics on a configurable timer interval. The collector can be
/// enabled/disabled and the interval adjusted at runtime.
///
/// Typical usage: a timer interrupt calls [`VmstatCollector::tick`]
/// which checks the interval and folds dirty per-CPU counters into
/// zone and global arrays.
pub struct VmstatCollector {
    /// Per-CPU differential counters.
    per_cpu: [PerCpuVmstat; MAX_CPUS],
    /// Per-zone aggregated counters.
    zones: [ZoneVmstat; MAX_ZONES],
    /// Number of active zones.
    zone_count: usize,
    /// Global (system-wide) aggregated counters.
    global: [u64; NUM_COUNTERS],
    /// Collection interval in milliseconds.
    interval_ms: u64,
    /// Whether periodic collection is enabled.
    enabled: bool,
}

impl Default for VmstatCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl VmstatCollector {
    /// Creates a new collector with default settings.
    ///
    /// All counters start at zero, the interval is 1000 ms, and
    /// collection is enabled by default.
    pub const fn new() -> Self {
        const EMPTY_CPU: PerCpuVmstat = PerCpuVmstat::new(0);
        const EMPTY_ZONE: ZoneVmstat = ZoneVmstat::new(0);

        let mut per_cpu = [EMPTY_CPU; MAX_CPUS];
        let mut i = 0;
        while i < MAX_CPUS {
            per_cpu[i] = PerCpuVmstat::new(i as u32);
            i += 1;
        }

        Self {
            per_cpu,
            zones: [EMPTY_ZONE; MAX_ZONES],
            zone_count: 0,
            global: [0u64; NUM_COUNTERS],
            interval_ms: 1000,
            enabled: true,
        }
    }

    /// Fold per-CPU differential counters into global and zone totals.
    ///
    /// For each dirty per-CPU counter set, the deltas are applied to
    /// the global array, the per-CPU counters are zeroed, and the
    /// dirty flag is cleared. Zone counters for zone 0 (if active)
    /// also receive the deltas as a default aggregation target.
    pub fn fold_per_cpu(&mut self) {
        for cpu in self.per_cpu.iter_mut() {
            if !cpu.dirty {
                continue;
            }
            for idx in 0..NUM_COUNTERS {
                let delta = cpu.counters[idx];
                if delta == 0 {
                    continue;
                }
                // Apply to global counters.
                if delta >= 0 {
                    self.global[idx] = self.global[idx].saturating_add(delta as u64);
                } else {
                    self.global[idx] = self.global[idx].saturating_sub(delta.unsigned_abs());
                }
                // Apply to zone 0 as default target if zones are active.
                if self.zone_count > 0 {
                    self.zones[0].update(
                        // SAFETY: idx is always < NUM_COUNTERS, matching
                        // the enum's valid range. We reconstruct the enum
                        // to reuse ZoneVmstat::update's signed-delta logic.
                        counter_from_index(idx),
                        delta,
                    );
                }
                cpu.counters[idx] = 0;
            }
            cpu.reset_dirty();
        }
    }

    /// Periodic tick — should be called from a timer interrupt or
    /// kernel worker at the configured interval.
    ///
    /// If the collector is disabled, this is a no-op.
    pub fn tick(&mut self) {
        if !self.enabled {
            return;
        }
        self.fold_per_cpu();
    }

    /// Read a global counter value.
    pub fn get_global(&self, counter: VmstatCounter) -> u64 {
        self.global[counter.as_usize()]
    }

    /// Read a per-zone counter value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `zone_id` is out of range.
    pub fn get_zone(&self, zone_id: usize, counter: VmstatCounter) -> Result<u64> {
        if zone_id >= self.zone_count {
            return Err(Error::InvalidArgument);
        }
        Ok(self.zones[zone_id].get(counter))
    }

    /// Read a per-CPU differential counter value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of range.
    pub fn get_per_cpu(&self, cpu_id: usize, counter: VmstatCounter) -> Result<i64> {
        if cpu_id >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.per_cpu[cpu_id].get(counter))
    }

    /// Set the collection interval in milliseconds.
    pub fn set_interval(&mut self, ms: u64) {
        self.interval_ms = ms;
    }

    /// Enable periodic collection.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable periodic collection.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Return a snapshot (copy) of the global counter array.
    pub fn snapshot(&self) -> [u64; NUM_COUNTERS] {
        self.global
    }

    /// Force an immediate fold of all per-CPU counters.
    pub fn refresh(&mut self) {
        self.fold_per_cpu();
    }
}

/// Map a raw index back to a [`VmstatCounter`] variant.
///
/// Indices outside the valid range default to [`VmstatCounter::NrFreePages`].
const fn counter_from_index(idx: usize) -> VmstatCounter {
    match idx {
        0 => VmstatCounter::NrFreePages,
        1 => VmstatCounter::NrActiveAnon,
        2 => VmstatCounter::NrInactiveAnon,
        3 => VmstatCounter::NrActiveFile,
        4 => VmstatCounter::NrInactiveFile,
        5 => VmstatCounter::NrUnevictable,
        6 => VmstatCounter::NrMlocked,
        7 => VmstatCounter::NrDirty,
        8 => VmstatCounter::NrWriteback,
        9 => VmstatCounter::NrSlab,
        10 => VmstatCounter::NrPageTablePages,
        11 => VmstatCounter::NrKernelStack,
        12 => VmstatCounter::NrBounce,
        13 => VmstatCounter::NrZspages,
        14 => VmstatCounter::NrFreeCma,
        15 => VmstatCounter::NumaHit,
        16 => VmstatCounter::NumaMiss,
        17 => VmstatCounter::NumaForeign,
        18 => VmstatCounter::NumaInterleave,
        19 => VmstatCounter::NumaLocal,
        20 => VmstatCounter::NumaOther,
        _ => VmstatCounter::NrFreePages,
    }
}
