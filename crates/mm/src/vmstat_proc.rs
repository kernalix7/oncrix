// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `/proc/vmstat`, `/proc/buddyinfo`, and `/proc/pagetypeinfo`
//! formatting.
//!
//! Provides the data structures and formatting logic for the proc
//! filesystem entries that expose VM statistics to user space:
//!
//! - **`/proc/vmstat`** — flat key-value counters for page
//!   allocation, reclaim, compaction, THP, NUMA, and other VM
//!   events.
//! - **`/proc/buddyinfo`** — per-zone free page counts at each
//!   buddy allocator order (0..MAX_ORDER).
//! - **`/proc/pagetypeinfo`** — per-zone, per-migratetype free
//!   page counts at each order.
//!
//! The counters are accumulated from per-CPU differentials by a
//! periodic tick (see [`VmstatAccumulator::tick`]).
//!
//! # Architecture
//!
//! - [`VmstatEventCounter`] — identifiers for VM event counters
//! - [`VmstatCounters`] — aggregated global VM counters
//! - [`ZoneBuddyInfo`] — per-zone buddy allocator free counts
//! - [`PageTypeInfo`] — per-zone, per-migratetype breakdown
//! - [`PerCpuDiff`] — per-CPU differential counters
//! - [`VmstatAccumulator`] — periodic fold of per-CPU diffs into
//!   global counters
//! - [`VmstatProcFormatter`] — renders counters into proc-style
//!   text output
//!
//! Reference: Linux `mm/vmstat.c`, `fs/proc/vmstat.c`,
//! `mm/page_alloc.c` (buddyinfo).

use core::fmt::Write;
use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum buddy allocator order (2^MAX_ORDER pages).
const MAX_ORDER: usize = 11;

/// Maximum number of memory zones.
const MAX_ZONES: usize = 4;

/// Maximum number of migrate types.
const MAX_MIGRATE_TYPES: usize = 6;

/// Maximum number of CPUs for per-CPU diffs.
const MAX_CPUS: usize = 64;

/// Total number of VM event counter types.
const NUM_VM_EVENTS: usize = 36;

/// Maximum length of a zone name.
const MAX_ZONE_NAME: usize = 16;

/// Maximum output buffer size for formatted text.
const MAX_FORMAT_BUF: usize = 4096;

// -------------------------------------------------------------------
// VmstatEventCounter
// -------------------------------------------------------------------

/// Identifiers for VM event counters exposed via `/proc/vmstat`.
///
/// Each variant maps to an index in the counter arrays. The
/// ordering loosely follows Linux's `/proc/vmstat` output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmstatEventCounter {
    /// Pages allocated from the buddy allocator.
    PgAllocNormal = 0,
    /// Pages allocated from DMA zone.
    PgAllocDma = 1,
    /// Pages allocated from Movable zone.
    PgAllocMovable = 2,
    /// Pages freed back to the buddy allocator.
    PgFree = 3,
    /// Pages activated (moved to active LRU).
    PgActivate = 4,
    /// Pages deactivated (moved to inactive LRU).
    PgDeactivate = 5,
    /// Page faults (total).
    PgFault = 6,
    /// Major page faults (required I/O).
    PgMajFault = 7,
    /// Pages refilled (kswapd refill).
    PgRefill = 8,
    /// Pages scanned by kswapd.
    PgScan = 9,
    /// Pages stolen (reclaimed) by kswapd.
    PgSteal = 10,
    /// Pages scanned during direct reclaim.
    PgScanDirect = 11,
    /// Pages stolen during direct reclaim.
    PgStealDirect = 12,
    /// Pages paged in from storage.
    PgPgIn = 13,
    /// Pages paged out to storage.
    PgPgOut = 14,
    /// Pages swapped in.
    PsWapIn = 15,
    /// Pages swapped out.
    PsWapOut = 16,
    /// Compaction pages migrated.
    CompactMigrate = 17,
    /// Compaction free pages scanned.
    CompactFreeScanned = 18,
    /// Compaction migrate pages scanned.
    CompactMigrateScanned = 19,
    /// Compaction stalls (allocation retries).
    CompactStall = 20,
    /// Compaction failures.
    CompactFail = 21,
    /// Compaction successes.
    CompactSuccess = 22,
    /// THP fault allocations.
    ThpFaultAlloc = 23,
    /// THP fault allocation failures.
    ThpFaultFallback = 24,
    /// THP collapse allocations.
    ThpCollapseAlloc = 25,
    /// THP collapse failures.
    ThpCollapseFail = 26,
    /// THP splits.
    ThpSplit = 27,
    /// NUMA pages migrated.
    NumaPteUpdates = 28,
    /// NUMA hint faults.
    NumaHintFaults = 29,
    /// NUMA hint faults (local node).
    NumaHintFaultsLocal = 30,
    /// NUMA pages migrated.
    NumaPagesMigrated = 31,
    /// Balloon inflate events.
    BalloonInflate = 32,
    /// Balloon deflate events.
    BalloonDeflate = 33,
    /// OOM kills.
    OomKill = 34,
    /// Unevictable pages culled.
    UnevictablePgsCulled = 35,
}

impl VmstatEventCounter {
    /// Returns the counter index.
    const fn index(self) -> usize {
        self as usize
    }

    /// Returns the `/proc/vmstat` key name for this counter.
    pub const fn name(self) -> &'static str {
        match self {
            Self::PgAllocNormal => "pgalloc_normal",
            Self::PgAllocDma => "pgalloc_dma",
            Self::PgAllocMovable => "pgalloc_movable",
            Self::PgFree => "pgfree",
            Self::PgActivate => "pgactivate",
            Self::PgDeactivate => "pgdeactivate",
            Self::PgFault => "pgfault",
            Self::PgMajFault => "pgmajfault",
            Self::PgRefill => "pgrefill",
            Self::PgScan => "pgscan_kswapd",
            Self::PgSteal => "pgsteal_kswapd",
            Self::PgScanDirect => "pgscan_direct",
            Self::PgStealDirect => "pgsteal_direct",
            Self::PgPgIn => "pgpgin",
            Self::PgPgOut => "pgpgout",
            Self::PsWapIn => "pswpin",
            Self::PsWapOut => "pswpout",
            Self::CompactMigrate => "compact_migrate",
            Self::CompactFreeScanned => "compact_free_scanned",
            Self::CompactMigrateScanned => "compact_migrate_scanned",
            Self::CompactStall => "compact_stall",
            Self::CompactFail => "compact_fail",
            Self::CompactSuccess => "compact_success",
            Self::ThpFaultAlloc => "thp_fault_alloc",
            Self::ThpFaultFallback => "thp_fault_fallback",
            Self::ThpCollapseAlloc => "thp_collapse_alloc",
            Self::ThpCollapseFail => "thp_collapse_alloc_failed",
            Self::ThpSplit => "thp_split_page",
            Self::NumaPteUpdates => "numa_pte_updates",
            Self::NumaHintFaults => "numa_hint_faults",
            Self::NumaHintFaultsLocal => "numa_hint_faults_local",
            Self::NumaPagesMigrated => "numa_pages_migrated",
            Self::BalloonInflate => "balloon_inflate",
            Self::BalloonDeflate => "balloon_deflate",
            Self::OomKill => "oom_kill",
            Self::UnevictablePgsCulled => "unevictable_pgs_culled",
        }
    }
}

/// All counter variants in order, for iteration.
const ALL_COUNTERS: [VmstatEventCounter; NUM_VM_EVENTS] = [
    VmstatEventCounter::PgAllocNormal,
    VmstatEventCounter::PgAllocDma,
    VmstatEventCounter::PgAllocMovable,
    VmstatEventCounter::PgFree,
    VmstatEventCounter::PgActivate,
    VmstatEventCounter::PgDeactivate,
    VmstatEventCounter::PgFault,
    VmstatEventCounter::PgMajFault,
    VmstatEventCounter::PgRefill,
    VmstatEventCounter::PgScan,
    VmstatEventCounter::PgSteal,
    VmstatEventCounter::PgScanDirect,
    VmstatEventCounter::PgStealDirect,
    VmstatEventCounter::PgPgIn,
    VmstatEventCounter::PgPgOut,
    VmstatEventCounter::PsWapIn,
    VmstatEventCounter::PsWapOut,
    VmstatEventCounter::CompactMigrate,
    VmstatEventCounter::CompactFreeScanned,
    VmstatEventCounter::CompactMigrateScanned,
    VmstatEventCounter::CompactStall,
    VmstatEventCounter::CompactFail,
    VmstatEventCounter::CompactSuccess,
    VmstatEventCounter::ThpFaultAlloc,
    VmstatEventCounter::ThpFaultFallback,
    VmstatEventCounter::ThpCollapseAlloc,
    VmstatEventCounter::ThpCollapseFail,
    VmstatEventCounter::ThpSplit,
    VmstatEventCounter::NumaPteUpdates,
    VmstatEventCounter::NumaHintFaults,
    VmstatEventCounter::NumaHintFaultsLocal,
    VmstatEventCounter::NumaPagesMigrated,
    VmstatEventCounter::BalloonInflate,
    VmstatEventCounter::BalloonDeflate,
    VmstatEventCounter::OomKill,
    VmstatEventCounter::UnevictablePgsCulled,
];

// -------------------------------------------------------------------
// VmstatCounters
// -------------------------------------------------------------------

/// Aggregated global VM event counters.
#[derive(Debug, Clone, Copy)]
pub struct VmstatCounters {
    /// Counter values indexed by [`VmstatEventCounter`].
    pub values: [u64; NUM_VM_EVENTS],
}

impl Default for VmstatCounters {
    fn default() -> Self {
        Self::new()
    }
}

impl VmstatCounters {
    /// Creates zeroed counters.
    pub const fn new() -> Self {
        Self {
            values: [0u64; NUM_VM_EVENTS],
        }
    }

    /// Returns the value of a counter.
    pub const fn get(&self, counter: VmstatEventCounter) -> u64 {
        self.values[counter.index()]
    }

    /// Increments a counter by `delta`.
    pub fn add(&mut self, counter: VmstatEventCounter, delta: u64) {
        self.values[counter.index()] = self.values[counter.index()].saturating_add(delta);
    }

    /// Sets a counter to a specific value.
    pub fn set(&mut self, counter: VmstatEventCounter, value: u64) {
        self.values[counter.index()] = value;
    }
}

// -------------------------------------------------------------------
// ZoneName
// -------------------------------------------------------------------

/// Name of a memory zone (stored inline).
#[derive(Debug, Clone, Copy)]
pub struct ZoneName {
    /// Name bytes.
    bytes: [u8; MAX_ZONE_NAME],
    /// Length of the name.
    len: usize,
}

impl ZoneName {
    /// Creates a zone name from a byte slice.
    pub const fn from_bytes(name: &[u8]) -> Self {
        let mut bytes = [0u8; MAX_ZONE_NAME];
        let len = if name.len() > MAX_ZONE_NAME {
            MAX_ZONE_NAME
        } else {
            name.len()
        };
        let mut i = 0;
        while i < len {
            bytes[i] = name[i];
            i += 1;
        }
        Self { bytes, len }
    }

    /// Returns the name as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

// -------------------------------------------------------------------
// MigrateTypeName
// -------------------------------------------------------------------

/// Migrate type classification for pagetypeinfo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MigrateType {
    /// Unmovable pages.
    #[default]
    Unmovable = 0,
    /// Movable pages.
    Movable = 1,
    /// Reclaimable pages.
    Reclaimable = 2,
    /// High-atomicity reserves.
    HighAtomic = 3,
    /// CMA pages.
    Cma = 4,
    /// Isolate pages.
    Isolate = 5,
}

impl MigrateType {
    /// Returns the display name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unmovable => "Unmovable",
            Self::Movable => "Movable",
            Self::Reclaimable => "Reclaimable",
            Self::HighAtomic => "HighAtomic",
            Self::Cma => "CMA",
            Self::Isolate => "Isolate",
        }
    }
}

/// All migrate types in order.
const ALL_MIGRATE_TYPES: [MigrateType; MAX_MIGRATE_TYPES] = [
    MigrateType::Unmovable,
    MigrateType::Movable,
    MigrateType::Reclaimable,
    MigrateType::HighAtomic,
    MigrateType::Cma,
    MigrateType::Isolate,
];

// -------------------------------------------------------------------
// ZoneBuddyInfo
// -------------------------------------------------------------------

/// Per-zone buddy allocator free page counts at each order.
///
/// `free_count[order]` is the number of free blocks of size
/// `2^order` pages.
#[derive(Debug, Clone, Copy)]
pub struct ZoneBuddyInfo {
    /// Zone name.
    pub name: ZoneName,
    /// NUMA node this zone belongs to.
    pub node: u8,
    /// Free block counts per order.
    pub free_count: [u64; MAX_ORDER],
    /// Whether this zone is active.
    pub active: bool,
}

impl ZoneBuddyInfo {
    /// Creates an empty, inactive zone.
    const fn empty() -> Self {
        Self {
            name: ZoneName::from_bytes(b""),
            node: 0,
            free_count: [0u64; MAX_ORDER],
            active: false,
        }
    }

    /// Returns the total free pages in this zone.
    pub fn total_free_pages(&self) -> u64 {
        let mut total = 0u64;
        let mut i = 0;
        while i < MAX_ORDER {
            total = total.saturating_add(self.free_count[i] << i);
            i += 1;
        }
        total
    }
}

// -------------------------------------------------------------------
// PageTypeInfo
// -------------------------------------------------------------------

/// Per-zone, per-migratetype free page counts at each order.
///
/// Provides the breakdown shown in `/proc/pagetypeinfo`.
#[derive(Debug, Clone, Copy)]
pub struct PageTypeInfo {
    /// Zone name.
    pub name: ZoneName,
    /// NUMA node.
    pub node: u8,
    /// Free counts: `counts[migrate_type][order]`.
    pub counts: [[u64; MAX_ORDER]; MAX_MIGRATE_TYPES],
    /// Whether this zone is active.
    pub active: bool,
}

impl PageTypeInfo {
    /// Creates an empty, inactive entry.
    const fn empty() -> Self {
        Self {
            name: ZoneName::from_bytes(b""),
            node: 0,
            counts: [[0u64; MAX_ORDER]; MAX_MIGRATE_TYPES],
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// PerCpuDiff
// -------------------------------------------------------------------

/// Per-CPU differential counters.
///
/// Each CPU accumulates counter increments locally. The
/// [`VmstatAccumulator`] periodically folds these diffs into the
/// global counters and resets them.
#[derive(Debug, Clone, Copy)]
pub struct PerCpuDiff {
    /// Counter diffs indexed by [`VmstatEventCounter`].
    pub diffs: [i64; NUM_VM_EVENTS],
    /// Whether this CPU slot is active.
    pub active: bool,
}

impl PerCpuDiff {
    /// Creates a zeroed, inactive per-CPU diff.
    const fn empty() -> Self {
        Self {
            diffs: [0i64; NUM_VM_EVENTS],
            active: false,
        }
    }

    /// Increments a counter diff.
    pub fn inc(&mut self, counter: VmstatEventCounter, delta: i64) {
        self.diffs[counter.index()] = self.diffs[counter.index()].saturating_add(delta);
    }

    /// Resets all diffs to zero.
    pub fn reset(&mut self) {
        self.diffs = [0i64; NUM_VM_EVENTS];
    }
}

// -------------------------------------------------------------------
// VmstatAccumulator
// -------------------------------------------------------------------

/// Periodic accumulator that folds per-CPU diffs into global
/// counters.
///
/// Manages per-CPU diff arrays, global counters, per-zone buddy
/// info, and pagetypeinfo. Call [`tick`](Self::tick) periodically
/// to fold diffs.
pub struct VmstatAccumulator {
    /// Global aggregated counters.
    pub counters: VmstatCounters,
    /// Per-CPU differential counters.
    cpus: [PerCpuDiff; MAX_CPUS],
    /// Number of active CPUs.
    cpu_count: usize,
    /// Per-zone buddy info.
    buddy_info: [ZoneBuddyInfo; MAX_ZONES],
    /// Number of active zones.
    zone_count: usize,
    /// Per-zone pagetypeinfo.
    pagetype_info: [PageTypeInfo; MAX_ZONES],
    /// Number of ticks performed.
    tick_count: u64,
}

impl Default for VmstatAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl VmstatAccumulator {
    /// Creates a new accumulator with no CPUs or zones.
    pub const fn new() -> Self {
        Self {
            counters: VmstatCounters::new(),
            cpus: [PerCpuDiff::empty(); MAX_CPUS],
            cpu_count: 0,
            buddy_info: [ZoneBuddyInfo::empty(); MAX_ZONES],
            zone_count: 0,
            pagetype_info: [PageTypeInfo::empty(); MAX_ZONES],
            tick_count: 0,
        }
    }

    // ---------------------------------------------------------------
    // CPU management
    // ---------------------------------------------------------------

    /// Registers a CPU for per-CPU diff tracking.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of
    /// range.
    /// Returns [`Error::AlreadyExists`] if the CPU is already
    /// registered.
    pub fn register_cpu(&mut self, cpu_id: usize) -> Result<()> {
        if cpu_id >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if self.cpus[cpu_id].active {
            return Err(Error::AlreadyExists);
        }
        self.cpus[cpu_id] = PerCpuDiff::empty();
        self.cpus[cpu_id].active = true;
        self.cpu_count += 1;
        Ok(())
    }

    /// Unregisters a CPU, folding its remaining diffs first.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of
    /// range.
    /// Returns [`Error::NotFound`] if the CPU is not registered.
    pub fn unregister_cpu(&mut self, cpu_id: usize) -> Result<()> {
        if cpu_id >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if !self.cpus[cpu_id].active {
            return Err(Error::NotFound);
        }
        // Fold remaining diffs.
        self.fold_cpu(cpu_id);
        self.cpus[cpu_id].active = false;
        self.cpu_count = self.cpu_count.saturating_sub(1);
        Ok(())
    }

    /// Increments a per-CPU counter diff.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of
    /// range or inactive.
    pub fn cpu_inc(
        &mut self,
        cpu_id: usize,
        counter: VmstatEventCounter,
        delta: i64,
    ) -> Result<()> {
        if cpu_id >= MAX_CPUS || !self.cpus[cpu_id].active {
            return Err(Error::InvalidArgument);
        }
        self.cpus[cpu_id].inc(counter, delta);
        Ok(())
    }

    // ---------------------------------------------------------------
    // Zone management
    // ---------------------------------------------------------------

    /// Registers a memory zone with buddy info.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all zone slots are full.
    pub fn register_zone(&mut self, name: &[u8], node: u8) -> Result<usize> {
        if self.zone_count >= MAX_ZONES {
            return Err(Error::OutOfMemory);
        }

        let idx = self.zone_count;
        self.buddy_info[idx] = ZoneBuddyInfo::empty();
        self.buddy_info[idx].name = ZoneName::from_bytes(name);
        self.buddy_info[idx].node = node;
        self.buddy_info[idx].active = true;

        self.pagetype_info[idx] = PageTypeInfo::empty();
        self.pagetype_info[idx].name = ZoneName::from_bytes(name);
        self.pagetype_info[idx].node = node;
        self.pagetype_info[idx].active = true;

        self.zone_count += 1;
        Ok(idx)
    }

    /// Updates the buddy free count for a zone at a specific order.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `zone_idx` or `order`
    /// is out of range.
    pub fn update_buddy(&mut self, zone_idx: usize, order: usize, free_count: u64) -> Result<()> {
        if zone_idx >= self.zone_count || order >= MAX_ORDER {
            return Err(Error::InvalidArgument);
        }
        self.buddy_info[zone_idx].free_count[order] = free_count;
        Ok(())
    }

    /// Updates a pagetypeinfo entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if any index is out of
    /// range.
    pub fn update_pagetype(
        &mut self,
        zone_idx: usize,
        migrate_type: usize,
        order: usize,
        count: u64,
    ) -> Result<()> {
        if zone_idx >= self.zone_count || migrate_type >= MAX_MIGRATE_TYPES || order >= MAX_ORDER {
            return Err(Error::InvalidArgument);
        }
        self.pagetype_info[zone_idx].counts[migrate_type][order] = count;
        Ok(())
    }

    // ---------------------------------------------------------------
    // Periodic tick
    // ---------------------------------------------------------------

    /// Folds all per-CPU diffs into global counters and resets
    /// the diffs.
    ///
    /// Should be called periodically (e.g., every second) by the
    /// vmstat shepherd thread.
    pub fn tick(&mut self) {
        for cpu_id in 0..MAX_CPUS {
            if self.cpus[cpu_id].active {
                self.fold_cpu(cpu_id);
            }
        }
        self.tick_count += 1;
    }

    /// Folds a single CPU's diffs into global counters.
    fn fold_cpu(&mut self, cpu_id: usize) {
        for i in 0..NUM_VM_EVENTS {
            let diff = self.cpus[cpu_id].diffs[i];
            if diff > 0 {
                self.counters.values[i] = self.counters.values[i].saturating_add(diff as u64);
            } else if diff < 0 {
                self.counters.values[i] = self.counters.values[i].saturating_sub((-diff) as u64);
            }
        }
        self.cpus[cpu_id].reset();
    }

    // ---------------------------------------------------------------
    // Accessors
    // ---------------------------------------------------------------

    /// Returns the global counter value.
    pub const fn get(&self, counter: VmstatEventCounter) -> u64 {
        self.counters.get(counter)
    }

    /// Returns the number of active CPUs.
    pub const fn cpu_count(&self) -> usize {
        self.cpu_count
    }

    /// Returns the number of active zones.
    pub const fn zone_count(&self) -> usize {
        self.zone_count
    }

    /// Returns the tick count.
    pub const fn tick_count(&self) -> u64 {
        self.tick_count
    }

    /// Returns a reference to the buddy info for a zone.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `zone_idx` is out of
    /// range.
    pub fn buddy_info(&self, zone_idx: usize) -> Result<&ZoneBuddyInfo> {
        if zone_idx >= self.zone_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.buddy_info[zone_idx])
    }

    /// Returns a reference to the pagetypeinfo for a zone.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `zone_idx` is out of
    /// range.
    pub fn pagetype_info(&self, zone_idx: usize) -> Result<&PageTypeInfo> {
        if zone_idx >= self.zone_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.pagetype_info[zone_idx])
    }
}

// -------------------------------------------------------------------
// VmstatProcFormatter
// -------------------------------------------------------------------

/// Renders VM statistics into proc-style text output.
///
/// Provides methods to format `/proc/vmstat`, `/proc/buddyinfo`,
/// and `/proc/pagetypeinfo` into a caller-provided buffer.
pub struct VmstatProcFormatter;

impl VmstatProcFormatter {
    /// Formats `/proc/vmstat` output into `buf`.
    ///
    /// Each line is `"key value\n"`. Returns the number of bytes
    /// written.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the buffer is too small.
    pub fn format_vmstat(acc: &VmstatAccumulator, buf: &mut [u8]) -> Result<usize> {
        let mut w = BufWriter::new(buf);

        for counter in &ALL_COUNTERS {
            let name = counter.name();
            let value = acc.counters.get(*counter);
            if write!(w, "{} {}\n", name, value).is_err() {
                return Err(Error::OutOfMemory);
            }
        }

        Ok(w.pos)
    }

    /// Formats `/proc/buddyinfo` output into `buf`.
    ///
    /// Each line:
    /// ```text
    /// Node N, zone   ZoneName  c0 c1 c2 ... c10
    /// ```
    ///
    /// Returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the buffer is too small.
    pub fn format_buddyinfo(acc: &VmstatAccumulator, buf: &mut [u8]) -> Result<usize> {
        let mut w = BufWriter::new(buf);

        for i in 0..acc.zone_count {
            let zi = &acc.buddy_info[i];
            if !zi.active {
                continue;
            }

            // "Node N, zone   ZoneName  "
            let zone_name = zi.name.as_bytes();
            if write!(
                w,
                "Node {:>3}, zone {:>8}",
                zi.node,
                core::str::from_utf8(zone_name).unwrap_or("?")
            )
            .is_err()
            {
                return Err(Error::OutOfMemory);
            }

            for order in 0..MAX_ORDER {
                if write!(w, " {:>6}", zi.free_count[order]).is_err() {
                    return Err(Error::OutOfMemory);
                }
            }

            if write!(w, "\n").is_err() {
                return Err(Error::OutOfMemory);
            }
        }

        Ok(w.pos)
    }

    /// Formats `/proc/pagetypeinfo` output into `buf`.
    ///
    /// Header line followed by per-zone, per-migratetype rows:
    /// ```text
    /// Node zone     type      o0 o1 o2 ... o10
    /// ```
    ///
    /// Returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the buffer is too small.
    pub fn format_pagetypeinfo(acc: &VmstatAccumulator, buf: &mut [u8]) -> Result<usize> {
        let mut w = BufWriter::new(buf);

        // Header.
        if write!(w, "Page block order: {:>3}\n", MAX_ORDER - 1).is_err() {
            return Err(Error::OutOfMemory);
        }

        // Column header.
        if write!(w, "{:<5} {:<8} {:<12}", "Node", "Zone", "Type").is_err() {
            return Err(Error::OutOfMemory);
        }
        for order in 0..MAX_ORDER {
            if write!(w, " {:>6}", order).is_err() {
                return Err(Error::OutOfMemory);
            }
        }
        if write!(w, "\n").is_err() {
            return Err(Error::OutOfMemory);
        }

        // Data rows.
        for zi in 0..acc.zone_count {
            let pt = &acc.pagetype_info[zi];
            if !pt.active {
                continue;
            }

            let zone_name = core::str::from_utf8(pt.name.as_bytes()).unwrap_or("?");

            for mt in &ALL_MIGRATE_TYPES {
                let mt_idx = *mt as usize;
                if write!(w, "{:<5} {:<8} {:<12}", pt.node, zone_name, mt.name()).is_err() {
                    return Err(Error::OutOfMemory);
                }

                for order in 0..MAX_ORDER {
                    if write!(w, " {:>6}", pt.counts[mt_idx][order]).is_err() {
                        return Err(Error::OutOfMemory);
                    }
                }

                if write!(w, "\n").is_err() {
                    return Err(Error::OutOfMemory);
                }
            }
        }

        Ok(w.pos)
    }
}

// -------------------------------------------------------------------
// BufWriter helper
// -------------------------------------------------------------------

/// Minimal no-alloc buffer writer implementing `core::fmt::Write`.
struct BufWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> BufWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }
}

impl Write for BufWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let remaining = self.buf.len() - self.pos;
        if bytes.len() > remaining {
            return Err(core::fmt::Error);
        }
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
        Ok(())
    }
}
