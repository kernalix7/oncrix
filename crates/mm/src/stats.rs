// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel memory statistics and `/proc/meminfo` formatting.
//!
//! Provides global memory counters, VM event tracking, zone-based
//! memory management info, and `/proc/meminfo` / `/proc/vmstat`
//! output formatting for the ONCRIX operating system.
//!
//! All counters use `u64` to avoid overflow in long-running systems.
//! Formatting functions write into caller-provided buffers to avoid
//! heap allocation in kernel context.
//!
//! Reference: `.kernelORG/` — `filesystems/proc.rst`,
//! `admin-guide/mm/`, `mm/vmstat.c`.

use core::fmt::Write;

use oncrix_lib::Result;

/// Page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of memory zones.
const MAX_ZONES: usize = 4;

/// Global memory statistics counters.
///
/// Tracks system-wide page counts by category. These counters
/// correspond to the fields exposed in `/proc/meminfo`.
#[derive(Debug, Clone, Copy)]
pub struct MemoryStats {
    /// Total physical pages in the system.
    pub total_pages: u64,
    /// Pages currently on the free list.
    pub free_pages: u64,
    /// Pages in active use (allocated, not free or cached).
    pub used_pages: u64,
    /// Pages used for page cache (file-backed).
    pub cached_pages: u64,
    /// Pages used by the slab allocator.
    pub slab_pages: u64,
    /// Pages shared between multiple processes.
    pub shared_pages: u64,
    /// Pages used by the kernel (text, data, stacks).
    pub kernel_pages: u64,
    /// Pages mapped into user-space address spaces.
    pub user_pages: u64,
}

impl MemoryStats {
    /// Create a new zeroed `MemoryStats`.
    pub const fn new() -> Self {
        Self {
            total_pages: 0,
            free_pages: 0,
            used_pages: 0,
            cached_pages: 0,
            slab_pages: 0,
            shared_pages: 0,
            kernel_pages: 0,
            user_pages: 0,
        }
    }

    /// Convert a page count to kibibytes (KiB).
    const fn pages_to_kib(pages: u64) -> u64 {
        pages * (PAGE_SIZE / 1024)
    }

    /// Estimated available memory (free + reclaimable cache).
    ///
    /// Approximates `MemAvailable` from Linux's `/proc/meminfo`:
    /// free pages plus half of cached pages (conservative estimate
    /// of reclaimable memory).
    pub const fn available_pages(&self) -> u64 {
        self.free_pages + self.cached_pages / 2
    }

    /// Total memory in kibibytes.
    pub const fn total_kib(&self) -> u64 {
        Self::pages_to_kib(self.total_pages)
    }

    /// Free memory in kibibytes.
    pub const fn free_kib(&self) -> u64 {
        Self::pages_to_kib(self.free_pages)
    }

    /// Available memory in kibibytes.
    pub const fn available_kib(&self) -> u64 {
        Self::pages_to_kib(self.available_pages())
    }
}

impl Default for MemoryStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Virtual memory event counters.
///
/// Tracks VM subsystem events for diagnostics and performance
/// monitoring. Exposed via `/proc/vmstat`.
#[derive(Debug, Clone, Copy)]
pub struct VmStats {
    /// Total page faults (minor + major).
    pub page_faults: u64,
    /// Copy-on-write faults resolved.
    pub cow_faults: u64,
    /// Pages allocated from the frame allocator.
    pub page_allocs: u64,
    /// Pages returned to the frame allocator.
    pub page_frees: u64,
    /// `mmap` calls completed.
    pub mmap_count: u64,
    /// `munmap` calls completed.
    pub munmap_count: u64,
    /// Pages swapped in from disk.
    pub swap_in: u64,
    /// Pages swapped out to disk.
    pub swap_out: u64,
}

impl VmStats {
    /// Create a new zeroed `VmStats`.
    pub const fn new() -> Self {
        Self {
            page_faults: 0,
            cow_faults: 0,
            page_allocs: 0,
            page_frees: 0,
            mmap_count: 0,
            munmap_count: 0,
            swap_in: 0,
            swap_out: 0,
        }
    }
}

impl Default for VmStats {
    fn default() -> Self {
        Self::new()
    }
}

/// VM event types for use with [`record_event`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmEvent {
    /// A page fault occurred.
    PageFault,
    /// A copy-on-write fault was resolved.
    CowFault,
    /// A page was allocated.
    PageAlloc,
    /// A page was freed.
    PageFree,
    /// An `mmap` call completed.
    Mmap,
    /// A `munmap` call completed.
    Munmap,
    /// A page was swapped in.
    SwapIn,
    /// A page was swapped out.
    SwapOut,
}

/// Memory zone type.
///
/// Physical memory is divided into zones based on address ranges,
/// following the classic DMA / Normal / HighMem split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneType {
    /// DMA zone: 0 — 16 MiB.
    ///
    /// Used for legacy ISA DMA that requires addresses below 16 MiB.
    Dma,
    /// Normal zone: 16 MiB — 4 GiB.
    ///
    /// Directly addressable memory for general kernel use.
    Normal,
    /// High memory zone: above 4 GiB.
    ///
    /// On 64-bit systems this is directly mapped, but kept as a
    /// separate zone for accounting and NUMA awareness.
    HighMem,
}

/// Information about a single memory zone.
///
/// Each zone tracks its address range, free page count, and
/// watermark levels that govern reclaim behavior.
#[derive(Debug, Clone, Copy)]
pub struct ZoneInfo {
    /// Zone type (DMA, Normal, HighMem).
    pub zone_type: ZoneType,
    /// Start physical address of this zone (bytes).
    pub start_addr: u64,
    /// End physical address of this zone (exclusive, bytes).
    pub end_addr: u64,
    /// Number of free pages in this zone.
    pub free_pages: u64,
    /// Total pages in this zone.
    pub total_pages: u64,
    /// Minimum watermark — below this, allocation fails.
    pub watermark_min: u64,
    /// Low watermark — below this, background reclaim starts.
    pub watermark_low: u64,
    /// High watermark — above this, reclaim stops.
    pub watermark_high: u64,
}

impl ZoneInfo {
    /// Create a new zone with the given type and address range.
    ///
    /// Watermarks are set to sensible defaults based on zone size.
    /// Free pages are initialized to zero; the caller must populate
    /// them after scanning the physical memory map.
    pub const fn new(zone_type: ZoneType, start_addr: u64, end_addr: u64) -> Self {
        let total = (end_addr - start_addr) / PAGE_SIZE;
        // Default watermarks: min=1%, low=2%, high=3% of zone size.
        let wm_min = total / 100;
        let wm_low = total / 50;
        let wm_high = total * 3 / 100;
        Self {
            zone_type,
            start_addr,
            end_addr,
            free_pages: 0,
            total_pages: total,
            watermark_min: if wm_min == 0 { 1 } else { wm_min },
            watermark_low: if wm_low == 0 { 2 } else { wm_low },
            watermark_high: if wm_high == 0 { 3 } else { wm_high },
        }
    }

    /// Check whether allocation is possible (free > min watermark).
    pub const fn can_allocate(&self) -> bool {
        self.free_pages > self.watermark_min
    }

    /// Check whether background reclaim should run.
    pub const fn needs_reclaim(&self) -> bool {
        self.free_pages < self.watermark_low
    }
}

/// Zone allocation policy — preference order for zone selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ZonePolicy {
    /// Prefer Normal, fall back to DMA, then HighMem.
    #[default]
    NormalFirst,
    /// Require DMA zone (for legacy device drivers).
    DmaOnly,
    /// Prefer HighMem, fall back to Normal, then DMA.
    HighMemFirst,
}

/// Collection of memory zones with an allocation policy.
///
/// Manages up to [`MAX_ZONES`] zones and provides zone selection
/// based on the configured [`ZonePolicy`].
#[derive(Debug)]
pub struct MemoryZones {
    /// Active zones.
    zones: [Option<ZoneInfo>; MAX_ZONES],
    /// Number of active zones.
    count: usize,
    /// Current allocation policy.
    policy: ZonePolicy,
}

impl MemoryZones {
    /// Create a new empty zone collection with the default policy.
    pub const fn new() -> Self {
        const NONE_ZONE: Option<ZoneInfo> = None;
        Self {
            zones: [NONE_ZONE; MAX_ZONES],
            count: 0,
            policy: ZonePolicy::NormalFirst,
        }
    }

    /// Add a zone to the collection.
    ///
    /// Returns `Err(InvalidArgument)` if the collection is full.
    pub fn add_zone(&mut self, zone: ZoneInfo) -> Result<()> {
        if self.count >= MAX_ZONES {
            return Err(oncrix_lib::Error::InvalidArgument);
        }
        for slot in self.zones.iter_mut() {
            if slot.is_none() {
                *slot = Some(zone);
                self.count += 1;
                return Ok(());
            }
        }
        Err(oncrix_lib::Error::InvalidArgument)
    }

    /// Set the zone allocation policy.
    pub fn set_policy(&mut self, policy: ZonePolicy) {
        self.policy = policy;
    }

    /// Current allocation policy.
    pub fn policy(&self) -> ZonePolicy {
        self.policy
    }

    /// Number of active zones.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Get a zone by index.
    pub fn get(&self, index: usize) -> Option<&ZoneInfo> {
        self.zones.get(index)?.as_ref()
    }

    /// Get a mutable zone by index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut ZoneInfo> {
        self.zones.get_mut(index)?.as_mut()
    }

    /// Find the best zone for allocation according to the policy.
    ///
    /// Returns the index of the preferred zone that has capacity,
    /// or `None` if no zone can satisfy the request.
    pub fn select_zone(&self) -> Option<usize> {
        let order: &[ZoneType] = match self.policy {
            ZonePolicy::NormalFirst => &[ZoneType::Normal, ZoneType::Dma, ZoneType::HighMem],
            ZonePolicy::DmaOnly => &[ZoneType::Dma],
            ZonePolicy::HighMemFirst => &[ZoneType::HighMem, ZoneType::Normal, ZoneType::Dma],
        };

        for preferred in order {
            for (i, slot) in self.zones.iter().enumerate() {
                if let Some(zone) = slot {
                    if zone.zone_type == *preferred && zone.can_allocate() {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    /// Total free pages across all zones.
    pub fn total_free(&self) -> u64 {
        self.zones
            .iter()
            .filter_map(|z| z.as_ref())
            .map(|z| z.free_pages)
            .sum()
    }

    /// Total pages across all zones.
    pub fn total_pages(&self) -> u64 {
        self.zones
            .iter()
            .filter_map(|z| z.as_ref())
            .map(|z| z.total_pages)
            .sum()
    }
}

impl Default for MemoryZones {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-type page accounting.
///
/// Breaks down page usage by purpose for fine-grained memory
/// tracking, used in `/proc/meminfo` and OOM reporting.
#[derive(Debug, Clone, Copy)]
pub struct PageCounts {
    /// Anonymous pages (heap, stack, `mmap` `MAP_ANONYMOUS`).
    pub anonymous: u64,
    /// File-backed pages (page cache, `mmap` of files).
    pub file_backed: u64,
    /// Pages used by slab allocators.
    pub slab: u64,
    /// Pages used for page table structures.
    pub page_table: u64,
    /// Pages used for kernel stacks.
    pub kernel_stack: u64,
}

impl PageCounts {
    /// Create a new zeroed `PageCounts`.
    pub const fn new() -> Self {
        Self {
            anonymous: 0,
            file_backed: 0,
            slab: 0,
            page_table: 0,
            kernel_stack: 0,
        }
    }

    /// Total pages across all categories.
    pub const fn total(&self) -> u64 {
        self.anonymous + self.file_backed + self.slab + self.page_table + self.kernel_stack
    }
}

impl Default for PageCounts {
    fn default() -> Self {
        Self::new()
    }
}

/// Page count category for use with [`update_stats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageCategory {
    /// Anonymous pages.
    Anonymous,
    /// File-backed pages.
    FileBacked,
    /// Slab pages.
    Slab,
    /// Page table pages.
    PageTable,
    /// Kernel stack pages.
    KernelStack,
}

/// Update `MemoryStats` counters from current zone and page data.
///
/// Recomputes derived fields (`used_pages`) from the authoritative
/// sources (zones and page counts).
pub fn update_stats(stats: &mut MemoryStats, zones: &MemoryZones, pages: &PageCounts) {
    stats.total_pages = zones.total_pages();
    stats.free_pages = zones.total_free();
    stats.used_pages = stats.total_pages.saturating_sub(stats.free_pages);
    stats.slab_pages = pages.slab;
    stats.kernel_pages = pages.kernel_stack + pages.page_table;
    stats.user_pages = pages.anonymous + pages.file_backed;
    stats.cached_pages = pages.file_backed;
}

/// Record a VM event by incrementing the appropriate counter.
pub fn record_event(vm: &mut VmStats, event: VmEvent) {
    match event {
        VmEvent::PageFault => vm.page_faults += 1,
        VmEvent::CowFault => vm.cow_faults += 1,
        VmEvent::PageAlloc => vm.page_allocs += 1,
        VmEvent::PageFree => vm.page_frees += 1,
        VmEvent::Mmap => vm.mmap_count += 1,
        VmEvent::Munmap => vm.munmap_count += 1,
        VmEvent::SwapIn => vm.swap_in += 1,
        VmEvent::SwapOut => vm.swap_out += 1,
    }
}

/// Update a specific page category counter by a signed delta.
///
/// Positive `delta` increases the count, negative decreases it.
/// The counter is clamped to zero on underflow.
pub fn update_page_count(pages: &mut PageCounts, category: PageCategory, delta: i64) {
    let counter = match category {
        PageCategory::Anonymous => &mut pages.anonymous,
        PageCategory::FileBacked => &mut pages.file_backed,
        PageCategory::Slab => &mut pages.slab,
        PageCategory::PageTable => &mut pages.page_table,
        PageCategory::KernelStack => &mut pages.kernel_stack,
    };
    if delta >= 0 {
        *counter = counter.saturating_add(delta as u64);
    } else {
        *counter = counter.saturating_sub(delta.unsigned_abs());
    }
}

/// Helper that writes a `/proc/meminfo`-style line: `key:  value kB\n`.
fn write_meminfo_line(buf: &mut BufWriter<'_>, key: &str, kib: u64) -> core::fmt::Result {
    // Linux right-pads keys to 16 chars and right-aligns values.
    writeln!(buf, "{:<16}{:>10} kB", key, kib)
}

/// Format `/proc/meminfo` output into the provided buffer.
///
/// Writes a Linux-compatible `/proc/meminfo` representation of the
/// current memory statistics. Returns the number of bytes written,
/// or `Err` if the buffer is too small.
///
/// Fields produced:
/// - `MemTotal`, `MemFree`, `MemAvailable`
/// - `Buffers`, `Cached`
/// - `SwapTotal`, `SwapFree`
/// - `Slab`, `KernelStack`, `PageTables`
/// - `AnonPages`, `Mapped`, `Shmem`
pub fn format_meminfo(buf: &mut [u8], stats: &MemoryStats, pages: &PageCounts) -> Result<usize> {
    let mut writer = BufWriter::new(buf);
    let r = (|| -> core::fmt::Result {
        let p = |n: u64| n * (PAGE_SIZE / 1024);
        write_meminfo_line(&mut writer, "MemTotal:", stats.total_kib())?;
        write_meminfo_line(&mut writer, "MemFree:", stats.free_kib())?;
        write_meminfo_line(&mut writer, "MemAvailable:", stats.available_kib())?;
        // Buffers: 0 for now (no block-layer buffer cache yet).
        write_meminfo_line(&mut writer, "Buffers:", 0)?;
        write_meminfo_line(&mut writer, "Cached:", p(stats.cached_pages))?;
        write_meminfo_line(&mut writer, "SwapTotal:", 0)?;
        write_meminfo_line(&mut writer, "SwapFree:", 0)?;
        write_meminfo_line(&mut writer, "Slab:", p(pages.slab))?;
        write_meminfo_line(&mut writer, "KernelStack:", p(pages.kernel_stack))?;
        write_meminfo_line(&mut writer, "PageTables:", p(pages.page_table))?;
        write_meminfo_line(&mut writer, "AnonPages:", p(pages.anonymous))?;
        write_meminfo_line(&mut writer, "Mapped:", p(pages.file_backed))?;
        write_meminfo_line(&mut writer, "Shmem:", p(stats.shared_pages))?;
        Ok(())
    })();

    match r {
        Ok(()) => Ok(writer.written),
        Err(_) => Err(oncrix_lib::Error::InvalidArgument),
    }
}

/// Format `/proc/vmstat` output into the provided buffer.
///
/// Writes key-value pairs (one per line) for all VM event counters.
/// Returns the number of bytes written, or `Err` if the buffer is
/// too small.
pub fn format_vmstat(buf: &mut [u8], vm: &VmStats) -> Result<usize> {
    let mut writer = BufWriter::new(buf);
    let r = (|| -> core::fmt::Result {
        writeln!(writer, "pgfault {}", vm.page_faults)?;
        writeln!(writer, "pgcow {}", vm.cow_faults)?;
        writeln!(writer, "pgalloc {}", vm.page_allocs)?;
        writeln!(writer, "pgfree {}", vm.page_frees)?;
        writeln!(writer, "mmap {}", vm.mmap_count)?;
        writeln!(writer, "munmap {}", vm.munmap_count)?;
        writeln!(writer, "pswpin {}", vm.swap_in)?;
        writeln!(writer, "pswpout {}", vm.swap_out)?;
        Ok(())
    })();

    match r {
        Ok(()) => Ok(writer.written),
        Err(_) => Err(oncrix_lib::Error::InvalidArgument),
    }
}

// -------------------------------------------------------------------
// MemInfo — comprehensive /proc/meminfo counters
// -------------------------------------------------------------------

/// Maximum number of NUMA nodes tracked.
const MAX_NUMA_NODES: usize = 8;

/// Maximum number of zones tracked by the collector.
const MAX_STAT_ZONES: usize = 8;

/// Comprehensive memory information counters, corresponding to
/// `/proc/meminfo` fields on Linux.
///
/// All values are in pages unless otherwise noted.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemInfo {
    /// Total physical pages in the system.
    pub total_pages: u64,
    /// Pages on the free list.
    pub free_pages: u64,
    /// Pages in active use (total − free − cached − buffers).
    pub used_pages: u64,
    /// Pages used for file-backed page cache.
    pub cached_pages: u64,
    /// Pages used by block-layer buffer cache.
    pub buffers_pages: u64,
    /// Total swap space in pages.
    pub swap_total: u64,
    /// Free swap space in pages.
    pub swap_free: u64,
    /// Used swap space in pages.
    pub swap_used: u64,
    /// Pages consumed by the slab allocator.
    pub slab_pages: u64,
    /// Pages used for page table structures.
    pub page_tables_pages: u64,
    /// Pages used for kernel thread stacks.
    pub kernel_stack_pages: u64,
    /// Total huge pages configured.
    pub huge_pages_total: u64,
    /// Free (unallocated) huge pages.
    pub huge_pages_free: u64,
    /// Huge pages currently in use.
    pub huge_pages_used: u64,
}

impl MemInfo {
    /// Creates a zeroed `MemInfo`.
    pub const fn new() -> Self {
        Self {
            total_pages: 0,
            free_pages: 0,
            used_pages: 0,
            cached_pages: 0,
            buffers_pages: 0,
            swap_total: 0,
            swap_free: 0,
            swap_used: 0,
            slab_pages: 0,
            page_tables_pages: 0,
            kernel_stack_pages: 0,
            huge_pages_total: 0,
            huge_pages_free: 0,
            huge_pages_used: 0,
        }
    }
}

impl Default for MemInfo {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// VmStat — VM event counters
// -------------------------------------------------------------------

/// Virtual-memory event counters for `/proc/vmstat`.
///
/// Each field is a monotonically increasing `u64` counter that
/// tracks a specific VM subsystem event since boot.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmStat {
    /// Pages paged in from disk.
    pub pgpgin: u64,
    /// Pages paged out to disk.
    pub pgpgout: u64,
    /// Total page faults (minor + major).
    pub pgfault: u64,
    /// Major page faults (required I/O).
    pub pgmajfault: u64,
    /// Pages swapped in.
    pub pswpin: u64,
    /// Pages swapped out.
    pub pswpout: u64,
    /// Pages allocated from the frame allocator.
    pub pgalloc: u64,
    /// Pages returned to the frame allocator.
    pub pgfree: u64,
    /// Pages moved to the active list.
    pub pgactivate: u64,
    /// Pages moved to the inactive list.
    pub pgdeactivate: u64,
    /// Pages lazy-freed (deferred reclaim).
    pub pglazyfreed: u64,
    /// Times compaction stalled waiting for pages.
    pub compact_stall: u64,
    /// Successful compaction runs.
    pub compact_success: u64,
    /// OOM kills triggered.
    pub oom_kill: u64,
}

impl VmStat {
    /// Creates a zeroed `VmStat`.
    pub const fn new() -> Self {
        Self {
            pgpgin: 0,
            pgpgout: 0,
            pgfault: 0,
            pgmajfault: 0,
            pswpin: 0,
            pswpout: 0,
            pgalloc: 0,
            pgfree: 0,
            pgactivate: 0,
            pgdeactivate: 0,
            pglazyfreed: 0,
            compact_stall: 0,
            compact_success: 0,
            oom_kill: 0,
        }
    }
}

// -------------------------------------------------------------------
// NumaStat — per-NUMA-node statistics
// -------------------------------------------------------------------

/// Per-NUMA-node memory statistics.
///
/// Tracks page placement locality for NUMA-aware scheduling and
/// memory policy decisions.
#[derive(Debug, Clone, Copy, Default)]
pub struct NumaStat {
    /// NUMA node identifier.
    pub node_id: u32,
    /// Pages allocated locally (on the preferred node).
    pub local_pages: u64,
    /// Pages allocated remotely (on a non-preferred node).
    pub remote_pages: u64,
    /// Pages allocated via interleave policy.
    pub interleave_pages: u64,
}

impl NumaStat {
    /// Creates a zeroed `NumaStat`.
    pub const fn new() -> Self {
        Self {
            node_id: 0,
            local_pages: 0,
            remote_pages: 0,
            interleave_pages: 0,
        }
    }
}

// -------------------------------------------------------------------
// ZoneStat — per-zone statistics for the collector
// -------------------------------------------------------------------

/// Per-zone memory statistics for the stat collector.
///
/// Provides a compact summary of zone health, including watermark
/// levels that govern the page reclaim subsystem.
///
/// Note: this is separate from [`ZoneInfo`] which carries full
/// zone metadata including address ranges.
#[derive(Debug, Clone, Copy)]
pub struct ZoneStat {
    /// Zone identifier (index).
    pub zone_id: u32,
    /// Zone name (e.g., `b"DMA"`, `b"Normal"`).
    pub name: [u8; 16],
    /// Pages managed by the allocator in this zone.
    pub managed_pages: u64,
    /// Currently free pages.
    pub free_pages: u64,
    /// Minimum watermark — allocation fails below this.
    pub min_pages: u64,
    /// Low watermark — background reclaim starts below this.
    pub low_pages: u64,
    /// High watermark — reclaim stops above this.
    pub high_pages: u64,
    /// Total pages spanned by this zone (including holes).
    pub spanned_pages: u64,
}

impl ZoneStat {
    /// Creates a zeroed `ZoneStat`.
    pub const fn new() -> Self {
        Self {
            zone_id: 0,
            name: [0u8; 16],
            managed_pages: 0,
            free_pages: 0,
            min_pages: 0,
            low_pages: 0,
            high_pages: 0,
            spanned_pages: 0,
        }
    }
}

impl Default for ZoneStat {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MemStatCollector — aggregated memory statistics
// -------------------------------------------------------------------

/// Aggregated memory statistics collector.
///
/// Combines [`MemInfo`], [`VmStat`], per-node [`NumaStat`], and
/// per-zone [`ZoneStat`] into a single structure that can be
/// queried by `/proc` interfaces and the OOM killer.
pub struct MemStatCollector {
    /// System-wide memory information.
    meminfo: MemInfo,
    /// VM event counters.
    vmstat: VmStat,
    /// Per-NUMA-node statistics.
    numa_stats: [NumaStat; MAX_NUMA_NODES],
    /// Per-zone statistics.
    zone_info: [ZoneStat; MAX_STAT_ZONES],
    /// Number of active NUMA nodes.
    num_nodes: usize,
    /// Number of active zones.
    num_zones: usize,
}

impl Default for MemStatCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl MemStatCollector {
    /// Creates a new, zeroed `MemStatCollector`.
    pub const fn new() -> Self {
        const EMPTY_NUMA: NumaStat = NumaStat::new();
        const EMPTY_ZONE: ZoneStat = ZoneStat::new();
        Self {
            meminfo: MemInfo::new(),
            vmstat: VmStat::new(),
            numa_stats: [EMPTY_NUMA; MAX_NUMA_NODES],
            zone_info: [EMPTY_ZONE; MAX_STAT_ZONES],
            num_nodes: 0,
            num_zones: 0,
        }
    }

    /// Recomputes `meminfo` derived fields.
    ///
    /// Sets `used_pages` from `total − free − cached − buffers`
    /// and `swap_used` from `swap_total − swap_free`.
    pub fn update_meminfo(&mut self) {
        self.meminfo.used_pages = self
            .meminfo
            .total_pages
            .saturating_sub(self.meminfo.free_pages)
            .saturating_sub(self.meminfo.cached_pages)
            .saturating_sub(self.meminfo.buffers_pages);
        self.meminfo.swap_used = self
            .meminfo
            .swap_total
            .saturating_sub(self.meminfo.swap_free);
        self.meminfo.huge_pages_used = self
            .meminfo
            .huge_pages_total
            .saturating_sub(self.meminfo.huge_pages_free);
    }

    /// Recomputes `vmstat` aggregate counters from zone data.
    ///
    /// Currently a no-op placeholder; individual event recording
    /// functions keep `vmstat` up to date incrementally.
    pub fn update_vmstat(&mut self) {
        // Counters are maintained incrementally by the
        // `record_*` methods; nothing to recompute.
    }

    /// Records a page fault event.
    pub fn record_pgfault(&mut self) {
        self.vmstat.pgfault = self.vmstat.pgfault.saturating_add(1);
    }

    /// Records a page allocation event.
    pub fn record_pgalloc(&mut self) {
        self.vmstat.pgalloc = self.vmstat.pgalloc.saturating_add(1);
    }

    /// Records a page free event.
    pub fn record_pgfree(&mut self) {
        self.vmstat.pgfree = self.vmstat.pgfree.saturating_add(1);
    }

    /// Records a swap-in event.
    pub fn record_swap_in(&mut self) {
        self.vmstat.pswpin = self.vmstat.pswpin.saturating_add(1);
    }

    /// Records a swap-out event.
    pub fn record_swap_out(&mut self) {
        self.vmstat.pswpout = self.vmstat.pswpout.saturating_add(1);
    }

    /// Records an OOM kill event.
    pub fn record_oom_kill(&mut self) {
        self.vmstat.oom_kill = self.vmstat.oom_kill.saturating_add(1);
    }

    /// Returns a reference to the current memory information.
    pub fn get_meminfo(&self) -> &MemInfo {
        &self.meminfo
    }

    /// Returns a reference to the VM event counters.
    pub fn get_vmstat(&self) -> &VmStat {
        &self.vmstat
    }

    /// Returns per-node NUMA statistics.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `node` is out of
    /// range.
    pub fn get_numa_stat(&self, node: usize) -> oncrix_lib::Result<&NumaStat> {
        if node >= self.num_nodes {
            return Err(oncrix_lib::Error::InvalidArgument);
        }
        Ok(&self.numa_stats[node])
    }

    /// Returns per-zone statistics.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `zone` is out of
    /// range.
    pub fn get_zone_info(&self, zone: usize) -> oncrix_lib::Result<&ZoneStat> {
        if zone >= self.num_zones {
            return Err(oncrix_lib::Error::InvalidArgument);
        }
        Ok(&self.zone_info[zone])
    }

    /// Computes overall memory pressure as a percentage (0–100).
    ///
    /// Pressure is defined as:
    ///   `(total − free) * 100 / total`
    ///
    /// Returns 0 if `total_pages` is zero (no memory detected).
    pub fn memory_pressure(&self) -> u8 {
        if self.meminfo.total_pages == 0 {
            return 0;
        }
        let used = self
            .meminfo
            .total_pages
            .saturating_sub(self.meminfo.free_pages);
        let pct = used.saturating_mul(100) / self.meminfo.total_pages;
        if pct > 100 { 100 } else { pct as u8 }
    }
}

/// A minimal `core::fmt::Write` adapter over a byte slice.
///
/// Tracks how many bytes have been written and fails gracefully
/// when the buffer is exhausted.
struct BufWriter<'a> {
    buf: &'a mut [u8],
    written: usize,
}

impl<'a> BufWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, written: 0 }
    }
}

impl Write for BufWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let remaining = self.buf.len() - self.written;
        if bytes.len() > remaining {
            return Err(core::fmt::Error);
        }
        self.buf[self.written..self.written + bytes.len()].copy_from_slice(bytes);
        self.written += bytes.len();
        Ok(())
    }
}
