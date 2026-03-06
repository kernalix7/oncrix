// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Vmstat per-CPU counters.
//!
//! Implements the per-CPU differential counter framework used by
//! `/proc/vmstat`. Each CPU accumulates counter deltas locally;
//! a periodic fold operation merges them into global counters.
//! This avoids contention on global state in hot allocation and
//! reclaim paths.
//!
//! - [`VmstatItem`] — counter identifiers (~40 items)
//! - [`PerCpuCounters`] — per-CPU delta arrays
//! - [`GlobalCounters`] — aggregated global counts
//! - [`VmstatCounterSet`] — the main counter management engine
//!
//! Reference: `.kernelORG/` — `mm/vmstat.c`, `include/linux/vmstat.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of CPUs.
const MAX_CPUS: usize = 8;

/// Number of vmstat counter items.
const NR_VMSTAT_ITEMS: usize = 40;

/// Fold threshold: fold when any per-CPU delta exceeds this.
const FOLD_THRESHOLD: i64 = 32;

// -------------------------------------------------------------------
// VmstatItem
// -------------------------------------------------------------------

/// Vmstat counter identifiers.
///
/// Each variant corresponds to an index into the counter arrays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VmstatItem {
    /// Number of free pages.
    #[default]
    NrFreePages = 0,
    /// Inactive anonymous pages.
    NrInactiveAnon = 1,
    /// Active anonymous pages.
    NrActiveAnon = 2,
    /// Inactive file pages.
    NrInactiveFile = 3,
    /// Active file pages.
    NrActiveFile = 4,
    /// Unevictable pages.
    NrUnevictable = 5,
    /// Mlocked pages.
    NrMlocked = 6,
    /// Dirty pages.
    NrDirty = 7,
    /// Pages under writeback.
    NrWriteback = 8,
    /// Slab reclaimable pages.
    NrSlabReclaimable = 9,
    /// Slab unreclaimable pages.
    NrSlabUnreclaimable = 10,
    /// Page table pages.
    NrPageTablePages = 11,
    /// Kernel stack pages.
    NrKernelStack = 12,
    /// Bounce buffer pages.
    NrBounce = 13,
    /// Mapped pages.
    NrMapped = 14,
    /// Anonymous pages.
    NrAnonPages = 15,
    /// Shared memory pages.
    NrShmem = 16,
    /// File pages.
    NrFilePages = 17,
    /// Writeback temporary pages.
    NrWritebackTemp = 18,
    /// Huge pages total.
    NrHugePages = 19,
    /// Huge pages free.
    NrHugePagesFree = 20,
    /// Pages allocated (cumulative).
    PgAllocNormal = 21,
    /// Pages allocated DMA.
    PgAllocDma = 22,
    /// Pages freed (cumulative).
    PgFree = 23,
    /// Page activations.
    PgActivate = 24,
    /// Page deactivations.
    PgDeactivate = 25,
    /// Page faults.
    PgFault = 26,
    /// Major page faults.
    PgMajFault = 27,
    /// Pages scanned by kswapd.
    PgscanKswapd = 28,
    /// Pages scanned directly.
    PgscanDirect = 29,
    /// Pages stolen by kswapd.
    PgstealKswapd = 30,
    /// Pages stolen directly.
    PgstealDirect = 31,
    /// Pages paged in.
    PgpgIn = 32,
    /// Pages paged out.
    PgpgOut = 33,
    /// Pages swapped in.
    PswpIn = 34,
    /// Pages swapped out.
    PswpOut = 35,
    /// Compact migration scanned.
    CompactMigrateScanned = 36,
    /// Compact free scanned.
    CompactFreeScanned = 37,
    /// Compact success.
    CompactSuccess = 38,
    /// Compact failure.
    CompactFail = 39,
}

impl VmstatItem {
    /// Returns the index of this item.
    fn index(self) -> usize {
        self as usize
    }

    /// Returns the name string for /proc/vmstat output.
    pub fn name(self) -> &'static str {
        match self {
            Self::NrFreePages => "nr_free_pages",
            Self::NrInactiveAnon => "nr_inactive_anon",
            Self::NrActiveAnon => "nr_active_anon",
            Self::NrInactiveFile => "nr_inactive_file",
            Self::NrActiveFile => "nr_active_file",
            Self::NrUnevictable => "nr_unevictable",
            Self::NrMlocked => "nr_mlock",
            Self::NrDirty => "nr_dirty",
            Self::NrWriteback => "nr_writeback",
            Self::NrSlabReclaimable => "nr_slab_reclaimable",
            Self::NrSlabUnreclaimable => "nr_slab_unreclaimable",
            Self::NrPageTablePages => "nr_page_table_pages",
            Self::NrKernelStack => "nr_kernel_stack",
            Self::NrBounce => "nr_bounce",
            Self::NrMapped => "nr_mapped",
            Self::NrAnonPages => "nr_anon_pages",
            Self::NrShmem => "nr_shmem",
            Self::NrFilePages => "nr_file_pages",
            Self::NrWritebackTemp => "nr_writeback_temp",
            Self::NrHugePages => "nr_huge_pages",
            Self::NrHugePagesFree => "nr_huge_pages_free",
            Self::PgAllocNormal => "pgalloc_normal",
            Self::PgAllocDma => "pgalloc_dma",
            Self::PgFree => "pgfree",
            Self::PgActivate => "pgactivate",
            Self::PgDeactivate => "pgdeactivate",
            Self::PgFault => "pgfault",
            Self::PgMajFault => "pgmajfault",
            Self::PgscanKswapd => "pgscan_kswapd",
            Self::PgscanDirect => "pgscan_direct",
            Self::PgstealKswapd => "pgsteal_kswapd",
            Self::PgstealDirect => "pgsteal_direct",
            Self::PgpgIn => "pgpgin",
            Self::PgpgOut => "pgpgout",
            Self::PswpIn => "pswpin",
            Self::PswpOut => "pswpout",
            Self::CompactMigrateScanned => "compact_migrate_scanned",
            Self::CompactFreeScanned => "compact_free_scanned",
            Self::CompactSuccess => "compact_success",
            Self::CompactFail => "compact_fail",
        }
    }
}

// -------------------------------------------------------------------
// PerCpuCounters
// -------------------------------------------------------------------

/// Per-CPU delta array for vmstat counters.
#[derive(Debug)]
pub struct PerCpuCounters {
    /// Delta values (can be negative).
    deltas: [i64; NR_VMSTAT_ITEMS],
    /// CPU ID.
    cpu_id: u32,
}

impl Default for PerCpuCounters {
    fn default() -> Self {
        Self {
            deltas: [0i64; NR_VMSTAT_ITEMS],
            cpu_id: 0,
        }
    }
}

impl PerCpuCounters {
    /// Creates counters for the given CPU.
    fn new(cpu_id: u32) -> Self {
        Self {
            cpu_id,
            ..Self::default()
        }
    }

    /// Increments a counter by the given amount.
    pub fn add(&mut self, item: VmstatItem, delta: i64) {
        self.deltas[item.index()] += delta;
    }

    /// Increments a counter by 1.
    pub fn inc(&mut self, item: VmstatItem) {
        self.deltas[item.index()] += 1;
    }

    /// Decrements a counter by 1.
    pub fn dec(&mut self, item: VmstatItem) {
        self.deltas[item.index()] -= 1;
    }

    /// Returns the current delta for an item.
    pub fn get(&self, item: VmstatItem) -> i64 {
        self.deltas[item.index()]
    }

    /// Returns `true` if any delta exceeds the fold threshold.
    pub fn needs_fold(&self) -> bool {
        self.deltas
            .iter()
            .any(|d| d.unsigned_abs() >= FOLD_THRESHOLD as u64)
    }

    /// Zeros all deltas (call after folding).
    fn reset(&mut self) {
        self.deltas = [0i64; NR_VMSTAT_ITEMS];
    }

    /// Returns the CPU ID.
    pub fn cpu_id(&self) -> u32 {
        self.cpu_id
    }
}

// -------------------------------------------------------------------
// GlobalCounters
// -------------------------------------------------------------------

/// Aggregated global vmstat counts.
#[derive(Debug)]
pub struct GlobalCounters {
    /// Global counter values.
    counts: [i64; NR_VMSTAT_ITEMS],
}

impl Default for GlobalCounters {
    fn default() -> Self {
        Self {
            counts: [0i64; NR_VMSTAT_ITEMS],
        }
    }
}

impl GlobalCounters {
    /// Returns the value of a global counter.
    pub fn get(&self, item: VmstatItem) -> i64 {
        self.counts[item.index()]
    }

    /// Adds a delta to a global counter.
    fn add(&mut self, item_index: usize, delta: i64) {
        if item_index < NR_VMSTAT_ITEMS {
            self.counts[item_index] += delta;
        }
    }

    /// Resets all global counters.
    pub fn reset(&mut self) {
        self.counts = [0i64; NR_VMSTAT_ITEMS];
    }
}

// -------------------------------------------------------------------
// VmstatCounterSet
// -------------------------------------------------------------------

/// The main vmstat counter management engine.
///
/// Holds per-CPU counters and global aggregates. Provides increment/
/// decrement operations on the per-CPU counters and periodic fold
/// to merge them into the global totals.
pub struct VmstatCounterSet {
    /// Per-CPU counter arrays.
    per_cpu: [PerCpuCounters; MAX_CPUS],
    /// Global counters.
    global: GlobalCounters,
    /// Number of active CPUs.
    nr_cpus: usize,
    /// Total fold operations performed.
    fold_count: u64,
}

impl Default for VmstatCounterSet {
    fn default() -> Self {
        Self {
            per_cpu: [const {
                PerCpuCounters {
                    deltas: [0i64; NR_VMSTAT_ITEMS],
                    cpu_id: 0,
                }
            }; MAX_CPUS],
            global: GlobalCounters::default(),
            nr_cpus: 1,
            fold_count: 0,
        }
    }
}

impl VmstatCounterSet {
    /// Creates a new counter set for the given number of CPUs.
    pub fn new(nr_cpus: usize) -> Self {
        let capped = nr_cpus.clamp(1, MAX_CPUS);
        let mut set = Self {
            nr_cpus: capped,
            ..Self::default()
        };
        for i in 0..capped {
            set.per_cpu[i] = PerCpuCounters::new(i as u32);
        }
        set
    }

    /// Increments a counter on the specified CPU.
    pub fn inc(&mut self, cpu: usize, item: VmstatItem) -> Result<()> {
        if cpu >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[cpu].inc(item);
        Ok(())
    }

    /// Decrements a counter on the specified CPU.
    pub fn dec(&mut self, cpu: usize, item: VmstatItem) -> Result<()> {
        if cpu >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[cpu].dec(item);
        Ok(())
    }

    /// Adds a delta to a counter on the specified CPU.
    pub fn add(&mut self, cpu: usize, item: VmstatItem, delta: i64) -> Result<()> {
        if cpu >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[cpu].add(item, delta);
        Ok(())
    }

    /// Folds all per-CPU deltas into the global counters.
    pub fn fold_all(&mut self) {
        for cpu in 0..self.nr_cpus {
            for item_idx in 0..NR_VMSTAT_ITEMS {
                let delta = self.per_cpu[cpu].deltas[item_idx];
                if delta != 0 {
                    self.global.add(item_idx, delta);
                }
            }
            self.per_cpu[cpu].reset();
        }
        self.fold_count += 1;
    }

    /// Folds only CPUs whose deltas exceed the threshold.
    pub fn fold_diff(&mut self) {
        for cpu in 0..self.nr_cpus {
            if self.per_cpu[cpu].needs_fold() {
                for item_idx in 0..NR_VMSTAT_ITEMS {
                    let delta = self.per_cpu[cpu].deltas[item_idx];
                    if delta != 0 {
                        self.global.add(item_idx, delta);
                    }
                }
                self.per_cpu[cpu].reset();
            }
        }
        self.fold_count += 1;
    }

    /// Refreshes: folds all then returns the global value for an
    /// item.
    pub fn refresh(&mut self, item: VmstatItem) -> i64 {
        self.fold_all();
        self.global.get(item)
    }

    /// Returns the current global value (without folding).
    pub fn global_count(&self, item: VmstatItem) -> i64 {
        self.global.get(item)
    }

    /// Returns a reference to the global counters.
    pub fn global(&self) -> &GlobalCounters {
        &self.global
    }

    /// Returns the per-CPU counters for a given CPU.
    pub fn per_cpu(&self, cpu: usize) -> Option<&PerCpuCounters> {
        if cpu < self.nr_cpus {
            Some(&self.per_cpu[cpu])
        } else {
            None
        }
    }

    /// Returns the number of fold operations performed.
    pub fn fold_count(&self) -> u64 {
        self.fold_count
    }

    /// Returns the number of active CPUs.
    pub fn nr_cpus(&self) -> usize {
        self.nr_cpus
    }
}
