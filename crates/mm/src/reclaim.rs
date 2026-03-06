// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page reclaim framework (kswapd + direct reclaim).
//!
//! Implements unified page reclaim for the ONCRIX kernel. When free
//! memory falls below configured watermarks, the reclaim subsystem
//! scans LRU lists to identify and evict pages that have not been
//! recently used.
//!
//! # Design
//!
//! The reclaim framework maintains per-zone LRU lists, categorized
//! by page type (anonymous vs. file-backed) and activity level
//! (active vs. inactive). Pages are demoted from active to inactive
//! before being reclaimed, implementing a second-chance algorithm.
//!
//! # Subsystems
//!
//! - [`ReclaimPriority`] — scan fraction control (0 = highest)
//! - [`ScanControl`] — per-reclaim-pass parameters and results
//! - [`LruList`] — LRU list classification
//! - [`LruPageEntry`] — a single page on an LRU list
//! - [`LruZone`] — per-zone LRU list set with page counts
//! - [`IsolatedPage`] — page isolated for reclaim processing
//! - [`ReclaimSubsystem`] — main reclaim engine with 4 zones
//! - [`ReclaimStats`] — aggregate reclaim statistics
//!
//! Reference: Linux `mm/vmscan.c`, `mm/swap.c`, `include/linux/mm_types.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of zones managed by the reclaim subsystem.
const MAX_ZONES: usize = 4;

/// Maximum number of pages per LRU list.
const MAX_LRU_PAGES: usize = 1024;

/// Maximum number of pages to isolate in a single scan pass.
const MAX_ISOLATED_PAGES: usize = 64;

/// Default inactive ratio: keep 1 inactive page for every 2 active.
const DEFAULT_INACTIVE_RATIO: u32 = 2;

/// Minimum number of pages to scan per priority level.
const MIN_SCAN_PAGES: u64 = 16;

/// Maximum reclaim priority (lowest urgency).
const MAX_PRIORITY: u8 = 12;

/// Page flag: page has been referenced since last scan.
const PAGE_REFERENCED: u32 = 1 << 0;

/// Page flag: page is dirty (needs writeback before reclaim).
const PAGE_DIRTY: u32 = 1 << 1;

/// Page flag: page is currently being written back.
const PAGE_WRITEBACK: u32 = 1 << 2;

/// Page flag: page is mapped in at least one page table.
const PAGE_MAPPED: u32 = 1 << 3;

/// Page flag: page is locked (cannot be reclaimed).
const PAGE_LOCKED: u32 = 1 << 4;

/// Page flag: page is swap-backed (anonymous).
const PAGE_SWAPBACKED: u32 = 1 << 5;

/// Page flag: page is unevictable.
const PAGE_UNEVICTABLE: u32 = 1 << 6;

/// Page flag: page has been recently activated.
const _PAGE_ACTIVATED: u32 = 1 << 7;

// -------------------------------------------------------------------
// ReclaimPriority
// -------------------------------------------------------------------

/// Reclaim scan priority.
///
/// Priority controls the fraction of pages scanned on each pass.
/// Priority 0 is the highest urgency (scan everything), while
/// priority 12 is the lowest (scan 1/4096 of the list).
///
/// The scan fraction is computed as:
///   `total_pages >> priority`
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReclaimPriority(u8);

impl ReclaimPriority {
    /// Highest priority — scan all pages.
    pub const HIGHEST: Self = Self(0);

    /// Default starting priority for background reclaim (kswapd).
    pub const DEFAULT: Self = Self(12);

    /// Create a new priority value.
    ///
    /// Clamps to `MAX_PRIORITY` if the supplied value exceeds it.
    pub const fn new(val: u8) -> Self {
        if val > MAX_PRIORITY {
            Self(MAX_PRIORITY)
        } else {
            Self(val)
        }
    }

    /// Raw priority value.
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Escalate priority by one level (decrease the value).
    ///
    /// Returns `None` if already at highest priority.
    pub const fn escalate(self) -> Option<Self> {
        if self.0 == 0 {
            None
        } else {
            Some(Self(self.0 - 1))
        }
    }

    /// Compute the number of pages to scan from a list of `total` pages.
    pub const fn scan_count(self, total: u64) -> u64 {
        let count = total >> self.0;
        if count < MIN_SCAN_PAGES && total >= MIN_SCAN_PAGES {
            MIN_SCAN_PAGES
        } else {
            count
        }
    }
}

impl Default for ReclaimPriority {
    fn default() -> Self {
        Self::DEFAULT
    }
}

// -------------------------------------------------------------------
// ScanControl
// -------------------------------------------------------------------

/// Per-reclaim-pass control parameters and result counters.
///
/// The caller sets the "input" fields before invoking reclaim;
/// the reclaim engine fills in the result counters.
#[derive(Debug, Clone, Copy)]
pub struct ScanControl {
    /// Current scan priority.
    pub priority: ReclaimPriority,
    /// Target number of pages to reclaim.
    pub nr_to_scan: u64,
    /// Number of pages successfully reclaimed (output).
    pub nr_reclaimed: u64,
    /// Number of pages scanned (output).
    pub nr_scanned: u64,
    /// Whether dirty pages may be written back.
    pub may_writeback: bool,
    /// Whether anonymous pages may be swapped out.
    pub may_swap: bool,
    /// Whether mapped pages may be unmapped.
    pub may_unmap: bool,
    /// Target zone index (0..MAX_ZONES).
    pub target_zone: u8,
    /// Whether this is a kswapd (background) reclaim.
    pub is_kswapd: bool,
    /// Whether the caller is in a memory-critical context.
    pub memcg_low_reclaim: bool,
}

impl ScanControl {
    /// Create a new scan control with default parameters.
    pub const fn new(nr_to_scan: u64, priority: ReclaimPriority) -> Self {
        Self {
            priority,
            nr_to_scan,
            nr_reclaimed: 0,
            nr_scanned: 0,
            may_writeback: true,
            may_swap: true,
            may_unmap: true,
            target_zone: 0,
            is_kswapd: false,
            memcg_low_reclaim: false,
        }
    }

    /// Reset the output counters for a new scan pass.
    pub fn reset_counters(&mut self) {
        self.nr_reclaimed = 0;
        self.nr_scanned = 0;
    }

    /// Whether the scan target has been met.
    pub const fn target_met(&self) -> bool {
        self.nr_reclaimed >= self.nr_to_scan
    }
}

impl Default for ScanControl {
    fn default() -> Self {
        Self::new(32, ReclaimPriority::DEFAULT)
    }
}

// -------------------------------------------------------------------
// LruList
// -------------------------------------------------------------------

/// LRU list classification.
///
/// Each zone maintains 6 LRU lists: active and inactive variants
/// for anonymous, file-backed, and unevictable pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LruList {
    /// Active anonymous pages (recently used, swap-backed).
    ActiveAnon,
    /// Inactive anonymous pages (candidates for swap-out).
    #[default]
    InactiveAnon,
    /// Active file-backed pages (recently used, backed by file).
    ActiveFile,
    /// Inactive file-backed pages (candidates for reclaim).
    InactiveFile,
    /// Active unevictable pages (mlock, etc.).
    UnevictableActive,
    /// Inactive unevictable pages (pending reclassification).
    UnevictableInactive,
}

impl LruList {
    /// Total number of LRU list types.
    pub const COUNT: usize = 6;

    /// Convert to an index (0..5) for array indexing.
    pub const fn index(self) -> usize {
        match self {
            Self::ActiveAnon => 0,
            Self::InactiveAnon => 1,
            Self::ActiveFile => 2,
            Self::InactiveFile => 3,
            Self::UnevictableActive => 4,
            Self::UnevictableInactive => 5,
        }
    }

    /// Whether this is an active list.
    pub const fn is_active(self) -> bool {
        matches!(
            self,
            Self::ActiveAnon | Self::ActiveFile | Self::UnevictableActive
        )
    }

    /// Whether this list contains anonymous (swap-backed) pages.
    pub const fn is_anon(self) -> bool {
        matches!(self, Self::ActiveAnon | Self::InactiveAnon)
    }

    /// Whether this list contains file-backed pages.
    pub const fn is_file(self) -> bool {
        matches!(self, Self::ActiveFile | Self::InactiveFile)
    }

    /// Whether this is an unevictable list.
    pub const fn is_unevictable(self) -> bool {
        matches!(self, Self::UnevictableActive | Self::UnevictableInactive)
    }

    /// Get the corresponding inactive list for an active one.
    pub const fn inactive_counterpart(self) -> Self {
        match self {
            Self::ActiveAnon => Self::InactiveAnon,
            Self::ActiveFile => Self::InactiveFile,
            Self::UnevictableActive => Self::UnevictableInactive,
            other => other,
        }
    }

    /// Get the corresponding active list for an inactive one.
    pub const fn active_counterpart(self) -> Self {
        match self {
            Self::InactiveAnon => Self::ActiveAnon,
            Self::InactiveFile => Self::ActiveFile,
            Self::UnevictableInactive => Self::UnevictableActive,
            other => other,
        }
    }
}

// -------------------------------------------------------------------
// LruPageEntry
// -------------------------------------------------------------------

/// A single page entry tracked on an LRU list.
#[derive(Debug, Clone, Copy)]
pub struct LruPageEntry {
    /// Page frame number.
    pub pfn: u64,
    /// Page flags (referenced, dirty, writeback, etc.).
    pub flags: u32,
    /// Which LRU list this page belongs to.
    pub lru: LruList,
    /// Reference count (number of mappings).
    pub map_count: u16,
    /// NUMA node this page belongs to.
    pub nid: u8,
    /// Whether this slot is in use.
    pub active: bool,
}

impl LruPageEntry {
    /// Create an empty (unused) LRU page entry.
    const fn empty() -> Self {
        Self {
            pfn: 0,
            flags: 0,
            lru: LruList::InactiveAnon,
            map_count: 0,
            nid: 0,
            active: false,
        }
    }

    /// Whether this page has been recently referenced.
    pub const fn is_referenced(&self) -> bool {
        self.flags & PAGE_REFERENCED != 0
    }

    /// Whether this page is dirty.
    pub const fn is_dirty(&self) -> bool {
        self.flags & PAGE_DIRTY != 0
    }

    /// Whether this page is being written back.
    pub const fn is_writeback(&self) -> bool {
        self.flags & PAGE_WRITEBACK != 0
    }

    /// Whether this page is mapped in a page table.
    pub const fn is_mapped(&self) -> bool {
        self.flags & PAGE_MAPPED != 0
    }

    /// Whether this page is locked.
    pub const fn is_locked(&self) -> bool {
        self.flags & PAGE_LOCKED != 0
    }

    /// Whether this page is swap-backed (anonymous).
    pub const fn is_swapbacked(&self) -> bool {
        self.flags & PAGE_SWAPBACKED != 0
    }

    /// Whether this page is unevictable.
    pub const fn is_unevictable(&self) -> bool {
        self.flags & PAGE_UNEVICTABLE != 0
    }

    /// Set the referenced flag.
    pub fn mark_referenced(&mut self) {
        self.flags |= PAGE_REFERENCED;
    }

    /// Clear the referenced flag.
    pub fn clear_referenced(&mut self) {
        self.flags &= !PAGE_REFERENCED;
    }

    /// Set the dirty flag.
    pub fn mark_dirty(&mut self) {
        self.flags |= PAGE_DIRTY;
    }

    /// Clear the dirty flag.
    pub fn clear_dirty(&mut self) {
        self.flags &= !PAGE_DIRTY;
    }
}

// -------------------------------------------------------------------
// IsolatedPage
// -------------------------------------------------------------------

/// A page that has been isolated from its LRU list for reclaim
/// processing.
#[derive(Debug, Clone, Copy)]
pub struct IsolatedPage {
    /// Page frame number.
    pub pfn: u64,
    /// Original LRU list this page was on.
    pub source_lru: LruList,
    /// Original page flags.
    pub flags: u32,
    /// Map count at time of isolation.
    pub map_count: u16,
    /// Whether reclaim was successful for this page.
    pub reclaimed: bool,
    /// Whether the page was put back on the LRU list.
    pub putback: bool,
}

impl IsolatedPage {
    /// Create an empty isolated page descriptor.
    const fn empty() -> Self {
        Self {
            pfn: 0,
            source_lru: LruList::InactiveAnon,
            flags: 0,
            map_count: 0,
            reclaimed: false,
            putback: false,
        }
    }
}

// -------------------------------------------------------------------
// LruZone
// -------------------------------------------------------------------

/// Per-zone LRU list set.
///
/// Maintains 6 LRU lists (active/inactive for anon, file, unevictable)
/// and tracks per-list page counts.
pub struct LruZone {
    /// Zone identifier (0..MAX_ZONES).
    zone_id: u8,
    /// Pages on each LRU list.
    lists: [[LruPageEntry; MAX_LRU_PAGES]; LruList::COUNT],
    /// Number of active entries on each list.
    counts: [u64; LruList::COUNT],
    /// Desired inactive ratio for anon pages.
    inactive_ratio_anon: u32,
    /// Desired inactive ratio for file pages.
    inactive_ratio_file: u32,
    /// Whether this zone is active.
    active: bool,
}

impl LruZone {
    /// Create a new empty LRU zone.
    fn new(zone_id: u8) -> Self {
        Self {
            zone_id,
            lists: [[const { LruPageEntry::empty() }; MAX_LRU_PAGES]; LruList::COUNT],
            counts: [0; LruList::COUNT],
            inactive_ratio_anon: DEFAULT_INACTIVE_RATIO,
            inactive_ratio_file: DEFAULT_INACTIVE_RATIO,
            active: false,
        }
    }

    /// Initialize this zone for use.
    pub fn init(&mut self, zone_id: u8) {
        self.zone_id = zone_id;
        self.active = true;
        self.counts = [0; LruList::COUNT];
        for list in &mut self.lists {
            for entry in list.iter_mut() {
                *entry = LruPageEntry::empty();
            }
        }
    }

    /// Zone identifier.
    pub const fn zone_id(&self) -> u8 {
        self.zone_id
    }

    /// Whether this zone is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Number of pages on a given LRU list.
    pub const fn list_count(&self, lru: LruList) -> u64 {
        self.counts[lru.index()]
    }

    /// Total number of pages across all LRU lists.
    pub fn total_pages(&self) -> u64 {
        let mut total: u64 = 0;
        let mut i = 0;
        while i < LruList::COUNT {
            total += self.counts[i];
            i += 1;
        }
        total
    }

    /// Total reclaimable pages (inactive anon + inactive file).
    pub fn reclaimable_pages(&self) -> u64 {
        self.counts[LruList::InactiveAnon.index()] + self.counts[LruList::InactiveFile.index()]
    }

    /// Add a page to the specified LRU list.
    pub fn add_page(
        &mut self,
        pfn: u64,
        flags: u32,
        lru: LruList,
        map_count: u16,
        nid: u8,
    ) -> Result<()> {
        if !self.active {
            return Err(Error::InvalidArgument);
        }
        let idx = lru.index();
        let list = &mut self.lists[idx];

        // Find a free slot.
        let slot = list.iter().position(|e| !e.active);
        let slot = match slot {
            Some(s) => s,
            None => return Err(Error::OutOfMemory),
        };

        list[slot] = LruPageEntry {
            pfn,
            flags,
            lru,
            map_count,
            nid,
            active: true,
        };
        self.counts[idx] += 1;
        Ok(())
    }

    /// Remove a page by PFN from its LRU list.
    pub fn remove_page(&mut self, pfn: u64, lru: LruList) -> Result<LruPageEntry> {
        let idx = lru.index();
        let list = &mut self.lists[idx];

        let pos = list.iter().position(|e| e.active && e.pfn == pfn);
        let pos = match pos {
            Some(p) => p,
            None => return Err(Error::NotFound),
        };

        let entry = list[pos];
        list[pos] = LruPageEntry::empty();
        self.counts[idx] = self.counts[idx].saturating_sub(1);
        Ok(entry)
    }

    /// Move a page from one LRU list to another.
    pub fn move_page(&mut self, pfn: u64, from: LruList, to: LruList) -> Result<()> {
        let entry = self.remove_page(pfn, from)?;
        self.add_page(pfn, entry.flags, to, entry.map_count, entry.nid)
    }

    /// Activate a page: move from inactive to active list.
    pub fn activate_page(&mut self, pfn: u64, lru: LruList) -> Result<()> {
        if lru.is_active() {
            return Ok(()); // already active
        }
        let target = lru.active_counterpart();
        self.move_page(pfn, lru, target)
    }

    /// Deactivate a page: move from active to inactive list.
    pub fn deactivate_page(&mut self, pfn: u64, lru: LruList) -> Result<()> {
        if !lru.is_active() {
            return Ok(()); // already inactive
        }
        let target = lru.inactive_counterpart();
        self.move_page(pfn, lru, target)
    }

    /// Check if the active/inactive ratio is balanced for anon pages.
    pub fn is_anon_balanced(&self) -> bool {
        let active = self.counts[LruList::ActiveAnon.index()];
        let inactive = self.counts[LruList::InactiveAnon.index()];
        if inactive == 0 {
            return active == 0;
        }
        active / inactive <= self.inactive_ratio_anon as u64
    }

    /// Check if the active/inactive ratio is balanced for file pages.
    pub fn is_file_balanced(&self) -> bool {
        let active = self.counts[LruList::ActiveFile.index()];
        let inactive = self.counts[LruList::InactiveFile.index()];
        if inactive == 0 {
            return active == 0;
        }
        active / inactive <= self.inactive_ratio_file as u64
    }

    /// Isolate up to `nr` inactive pages from the given LRU list.
    ///
    /// Isolated pages are removed from the list and returned in the
    /// output buffer. Pages that are locked or being written back
    /// are skipped.
    pub fn isolate_pages(
        &mut self,
        lru: LruList,
        nr: usize,
        buf: &mut [IsolatedPage; MAX_ISOLATED_PAGES],
    ) -> usize {
        let max = if nr > MAX_ISOLATED_PAGES {
            MAX_ISOLATED_PAGES
        } else {
            nr
        };
        let idx = lru.index();
        let mut isolated = 0;

        // Collect PFNs to isolate first (avoid borrow issues).
        let mut pfns_to_isolate = [0u64; MAX_ISOLATED_PAGES];
        let mut flags_buf = [0u32; MAX_ISOLATED_PAGES];
        let mut map_buf = [0u16; MAX_ISOLATED_PAGES];
        let mut count = 0;

        for entry in self.lists[idx].iter() {
            if count >= max {
                break;
            }
            if !entry.active {
                continue;
            }
            // Skip locked or writeback pages.
            if entry.is_locked() || entry.is_writeback() {
                continue;
            }
            pfns_to_isolate[count] = entry.pfn;
            flags_buf[count] = entry.flags;
            map_buf[count] = entry.map_count;
            count += 1;
        }

        // Now remove them from the list.
        for i in 0..count {
            let pfn = pfns_to_isolate[i];
            if self.remove_page(pfn, lru).is_ok() {
                buf[isolated] = IsolatedPage {
                    pfn,
                    source_lru: lru,
                    flags: flags_buf[i],
                    map_count: map_buf[i],
                    reclaimed: false,
                    putback: false,
                };
                isolated += 1;
            }
        }

        isolated
    }

    /// Put back pages that were not successfully reclaimed.
    pub fn putback_pages(
        &mut self,
        pages: &mut [IsolatedPage; MAX_ISOLATED_PAGES],
        count: usize,
    ) -> u64 {
        let mut putback_count: u64 = 0;
        for page in pages.iter_mut().take(count) {
            if page.reclaimed || page.putback {
                continue;
            }
            let result = self.add_page(page.pfn, page.flags, page.source_lru, page.map_count, 0);
            if result.is_ok() {
                page.putback = true;
                putback_count += 1;
            }
        }
        putback_count
    }
}

// -------------------------------------------------------------------
// ReclaimStats
// -------------------------------------------------------------------

/// Aggregate reclaim statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReclaimStats {
    /// Total pages scanned across all reclaim passes.
    pub pages_scanned: u64,
    /// Total pages successfully reclaimed.
    pub pages_reclaimed: u64,
    /// Pages that required writeback before reclaim.
    pub pages_writeback: u64,
    /// Pages that were activated (promoted to active list).
    pub pages_activated: u64,
    /// Pages that were deactivated (demoted to inactive list).
    pub pages_deactivated: u64,
    /// Number of direct reclaim invocations.
    pub direct_reclaim_calls: u64,
    /// Number of kswapd (background) reclaim passes.
    pub kswapd_reclaim_calls: u64,
    /// Number of times reclaim failed to free enough pages.
    pub reclaim_failures: u64,
    /// Pages put back on LRU after failed reclaim.
    pub pages_putback: u64,
    /// Pages isolated for reclaim processing.
    pub pages_isolated: u64,
}

impl ReclaimStats {
    /// Create zeroed stats.
    pub const fn new() -> Self {
        Self {
            pages_scanned: 0,
            pages_reclaimed: 0,
            pages_writeback: 0,
            pages_activated: 0,
            pages_deactivated: 0,
            direct_reclaim_calls: 0,
            kswapd_reclaim_calls: 0,
            reclaim_failures: 0,
            pages_putback: 0,
            pages_isolated: 0,
        }
    }

    /// Total number of reclaim passes (direct + kswapd).
    pub const fn total_reclaim_calls(&self) -> u64 {
        self.direct_reclaim_calls + self.kswapd_reclaim_calls
    }

    /// Reclaim efficiency: reclaimed / scanned ratio (0..100).
    pub const fn efficiency_percent(&self) -> u64 {
        if self.pages_scanned == 0 {
            return 0;
        }
        self.pages_reclaimed * 100 / self.pages_scanned
    }
}

// -------------------------------------------------------------------
// ReclaimSubsystem
// -------------------------------------------------------------------

/// Main page reclaim engine.
///
/// Manages up to 4 zones, each with their own LRU lists. Provides
/// `shrink_node` as the primary entry point for reclaiming pages.
pub struct ReclaimSubsystem {
    /// Per-zone LRU state.
    zones: [LruZone; MAX_ZONES],
    /// Number of active zones.
    nr_zones: usize,
    /// Aggregate reclaim statistics.
    stats: ReclaimStats,
    /// Whether the subsystem is initialized.
    initialized: bool,
    /// Global low watermark (pages below which direct reclaim triggers).
    watermark_low: u64,
    /// Global high watermark (pages above which kswapd stops).
    watermark_high: u64,
    /// Global min watermark (emergency reserve).
    watermark_min: u64,
}

impl ReclaimSubsystem {
    /// Create a new uninitialized reclaim subsystem.
    pub fn new() -> Self {
        Self {
            zones: [
                LruZone::new(0),
                LruZone::new(1),
                LruZone::new(2),
                LruZone::new(3),
            ],
            nr_zones: 0,
            stats: ReclaimStats::new(),
            initialized: false,
            watermark_low: 256,
            watermark_high: 512,
            watermark_min: 64,
        }
    }

    /// Initialize the reclaim subsystem with the given number of zones.
    pub fn init(&mut self, nr_zones: usize) -> Result<()> {
        if nr_zones > MAX_ZONES {
            return Err(Error::InvalidArgument);
        }
        for i in 0..nr_zones {
            self.zones[i].init(i as u8);
        }
        self.nr_zones = nr_zones;
        self.initialized = true;
        Ok(())
    }

    /// Whether the subsystem is initialized.
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Current reclaim statistics.
    pub const fn stats(&self) -> &ReclaimStats {
        &self.stats
    }

    /// Set watermark levels.
    pub fn set_watermarks(&mut self, min: u64, low: u64, high: u64) -> Result<()> {
        if min > low || low > high {
            return Err(Error::InvalidArgument);
        }
        self.watermark_min = min;
        self.watermark_low = low;
        self.watermark_high = high;
        Ok(())
    }

    /// Get a reference to a zone by index.
    pub fn zone(&self, idx: usize) -> Result<&LruZone> {
        if idx >= self.nr_zones {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.zones[idx])
    }

    /// Get a mutable reference to a zone by index.
    pub fn zone_mut(&mut self, idx: usize) -> Result<&mut LruZone> {
        if idx >= self.nr_zones {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.zones[idx])
    }

    /// Add a page to a zone's LRU list.
    pub fn add_page_to_lru(
        &mut self,
        zone_idx: usize,
        pfn: u64,
        flags: u32,
        lru: LruList,
    ) -> Result<()> {
        if zone_idx >= self.nr_zones {
            return Err(Error::InvalidArgument);
        }
        self.zones[zone_idx].add_page(pfn, flags, lru, 0, 0)
    }

    /// Total reclaimable pages across all zones.
    pub fn total_reclaimable(&self) -> u64 {
        let mut total: u64 = 0;
        for i in 0..self.nr_zones {
            total += self.zones[i].reclaimable_pages();
        }
        total
    }

    /// Total pages across all zones.
    pub fn total_lru_pages(&self) -> u64 {
        let mut total: u64 = 0;
        for i in 0..self.nr_zones {
            total += self.zones[i].total_pages();
        }
        total
    }

    /// Whether free memory is below the low watermark.
    pub fn needs_reclaim(&self, free_pages: u64) -> bool {
        free_pages < self.watermark_low
    }

    /// Whether free memory is below the min watermark (emergency).
    pub fn needs_emergency_reclaim(&self, free_pages: u64) -> bool {
        free_pages < self.watermark_min
    }

    /// Shrink a single zone's LRU list, attempting to reclaim pages.
    ///
    /// Scans the given LRU list, isolates candidate pages, and
    /// attempts to reclaim them. Pages that cannot be reclaimed
    /// (dirty and writeback not allowed, or locked) are put back.
    pub fn shrink_lru_list(
        &mut self,
        zone_idx: usize,
        lru: LruList,
        sc: &mut ScanControl,
    ) -> Result<u64> {
        if zone_idx >= self.nr_zones {
            return Err(Error::InvalidArgument);
        }

        let nr_to_isolate = sc.priority.scan_count(self.zones[zone_idx].list_count(lru));
        let nr_to_isolate = if nr_to_isolate > MAX_ISOLATED_PAGES as u64 {
            MAX_ISOLATED_PAGES
        } else {
            nr_to_isolate as usize
        };

        let mut isolated_buf = [const { IsolatedPage::empty() }; MAX_ISOLATED_PAGES];
        let nr_isolated = self.zones[zone_idx].isolate_pages(lru, nr_to_isolate, &mut isolated_buf);

        self.stats.pages_isolated += nr_isolated as u64;

        // Process each isolated page.
        let mut reclaimed: u64 = 0;
        for page in isolated_buf.iter_mut().take(nr_isolated) {
            sc.nr_scanned += 1;

            // Check referenced: if referenced, promote back.
            if page.flags & PAGE_REFERENCED != 0 {
                page.flags &= !PAGE_REFERENCED;
                page.putback = true;
                self.stats.pages_activated += 1;
                continue;
            }

            // Dirty page handling.
            if page.flags & PAGE_DIRTY != 0 {
                if sc.may_writeback {
                    self.stats.pages_writeback += 1;
                    page.flags &= !PAGE_DIRTY;
                    page.reclaimed = true;
                    reclaimed += 1;
                    continue;
                }
                page.putback = true;
                continue;
            }

            // Mapped page handling.
            if page.flags & PAGE_MAPPED != 0 && !sc.may_unmap {
                page.putback = true;
                continue;
            }

            // Swap-backed handling.
            if page.flags & PAGE_SWAPBACKED != 0 && !sc.may_swap {
                page.putback = true;
                continue;
            }

            // Unevictable pages should not be here but handle gracefully.
            if page.flags & PAGE_UNEVICTABLE != 0 {
                page.putback = true;
                continue;
            }

            // Page is clean and unmapped: reclaim it.
            page.reclaimed = true;
            reclaimed += 1;
        }

        // Put back pages that were not reclaimed.
        let putback = self.zones[zone_idx].putback_pages(&mut isolated_buf, nr_isolated);
        self.stats.pages_putback += putback;

        sc.nr_reclaimed += reclaimed;
        self.stats.pages_reclaimed += reclaimed;
        self.stats.pages_scanned += sc.nr_scanned;

        Ok(reclaimed)
    }

    /// Shrink a zone by scanning all eligible LRU lists.
    ///
    /// Scans inactive file pages first (cheapest to reclaim), then
    /// inactive anonymous pages if swap is allowed.
    pub fn shrink_zone(&mut self, zone_idx: usize, sc: &mut ScanControl) -> Result<u64> {
        if zone_idx >= self.nr_zones {
            return Err(Error::InvalidArgument);
        }

        let mut total_reclaimed: u64 = 0;

        // 1. Scan inactive file pages first.
        let reclaimed = self.shrink_lru_list(zone_idx, LruList::InactiveFile, sc)?;
        total_reclaimed += reclaimed;

        if sc.target_met() {
            return Ok(total_reclaimed);
        }

        // 2. Scan inactive anon pages.
        if sc.may_swap {
            let reclaimed = self.shrink_lru_list(zone_idx, LruList::InactiveAnon, sc)?;
            total_reclaimed += reclaimed;
        }

        if sc.target_met() {
            return Ok(total_reclaimed);
        }

        // 3. Deactivate active file pages to replenish inactive.
        if !self.zones[zone_idx].is_file_balanced() {
            self.rebalance_lru(zone_idx, LruList::ActiveFile)?;
        }

        // 4. Deactivate active anon pages if needed.
        if sc.may_swap && !self.zones[zone_idx].is_anon_balanced() {
            self.rebalance_lru(zone_idx, LruList::ActiveAnon)?;
        }

        Ok(total_reclaimed)
    }

    /// Rebalance a zone's LRU lists by demoting unreferenced active
    /// pages to their inactive counterpart.
    fn rebalance_lru(&mut self, zone_idx: usize, active_lru: LruList) -> Result<u64> {
        let inactive_lru = active_lru.inactive_counterpart();
        let idx = active_lru.index();
        let mut demoted: u64 = 0;

        // Collect PFNs of unreferenced pages.
        let mut pfns = [0u64; 32];
        let mut count = 0;

        for entry in self.zones[zone_idx].lists[idx].iter() {
            if count >= 32 {
                break;
            }
            if entry.active && !entry.is_referenced() {
                pfns[count] = entry.pfn;
                count += 1;
            }
        }

        for pfn in pfns.iter().take(count) {
            if self.zones[zone_idx]
                .move_page(*pfn, active_lru, inactive_lru)
                .is_ok()
            {
                demoted += 1;
                self.stats.pages_deactivated += 1;
            }
        }

        Ok(demoted)
    }

    /// Main reclaim entry point: shrink all zones to reclaim `nr_pages`.
    ///
    /// Iterates over zones with escalating priority until the target
    /// is met or the highest priority is exhausted.
    pub fn shrink_node(&mut self, nr_pages: u64, sc: &mut ScanControl) -> Result<u64> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }

        sc.nr_to_scan = nr_pages;
        sc.reset_counters();

        if sc.is_kswapd {
            self.stats.kswapd_reclaim_calls += 1;
        } else {
            self.stats.direct_reclaim_calls += 1;
        }

        let mut priority = sc.priority;

        loop {
            sc.priority = priority;

            for zone_idx in 0..self.nr_zones {
                if sc.target_met() {
                    return Ok(sc.nr_reclaimed);
                }
                let _ = self.shrink_zone(zone_idx, sc);
            }

            if sc.target_met() {
                return Ok(sc.nr_reclaimed);
            }

            // Escalate priority.
            match priority.escalate() {
                Some(p) => priority = p,
                None => break,
            }
        }

        if sc.nr_reclaimed == 0 {
            self.stats.reclaim_failures += 1;
        }

        Ok(sc.nr_reclaimed)
    }

    /// Reclaim a specific page by PFN from a zone.
    ///
    /// Searches all LRU lists for the page and removes it if found.
    pub fn reclaim_page(&mut self, zone_idx: usize, pfn: u64) -> Result<LruPageEntry> {
        if zone_idx >= self.nr_zones {
            return Err(Error::InvalidArgument);
        }

        // Try each list in order.
        let lists = [
            LruList::InactiveFile,
            LruList::InactiveAnon,
            LruList::ActiveFile,
            LruList::ActiveAnon,
        ];

        for lru in &lists {
            if let Ok(entry) = self.zones[zone_idx].remove_page(pfn, *lru) {
                self.stats.pages_reclaimed += 1;
                return Ok(entry);
            }
        }

        Err(Error::NotFound)
    }

    /// Memory pressure level: ratio of reclaimable to total LRU pages.
    ///
    /// Returns a percentage (0..100) where 100 means all pages are
    /// reclaimable and 0 means none are.
    pub fn pressure_percent(&self) -> u64 {
        let total = self.total_lru_pages();
        if total == 0 {
            return 0;
        }
        self.total_reclaimable() * 100 / total
    }

    /// Size in bytes of the pages tracked across all zones.
    pub fn total_tracked_bytes(&self) -> u64 {
        self.total_lru_pages() * PAGE_SIZE
    }
}

impl Default for ReclaimSubsystem {
    fn default() -> Self {
        Self::new()
    }
}
