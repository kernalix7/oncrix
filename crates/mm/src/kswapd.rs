// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! kswapd — kernel swap daemon for page reclaim.
//!
//! Implements the background page reclaim daemon that maintains free
//! memory watermarks by scanning LRU lists and reclaiming pages when
//! free memory drops below the low watermark. The daemon wakes
//! periodically or on-demand and scans pages at configurable
//! priorities (0 = most aggressive, 12 = lightest scan).
//!
//! # Architecture
//!
//! - [`LruList`] — doubly-linked LRU with active/inactive lists
//! - [`PageScanner`] — batch page scanning and candidate isolation
//! - [`ZoneWatermarks`] — per-zone high/low/min watermark thresholds
//! - [`KswapdConfig`] — tunables for scan behavior
//! - [`KswapdDaemon`] — main daemon state machine
//! - [`KswapdStats`] — reclaim statistics and counters
//!
//! Reference: Linux `mm/vmscan.c`, `mm/page_alloc.c` (watermarks).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of pages tracked in the LRU lists.
const MAX_LRU_PAGES: usize = 4096;

/// Maximum number of zones managed by kswapd.
const MAX_ZONES: usize = 4;

/// Maximum scan priority (lightest scan).
const MAX_SCAN_PRIORITY: u8 = 12;

/// Default number of pages to scan per batch.
const DEFAULT_BATCH_SIZE: usize = 32;

/// Maximum candidates that can be isolated per scan cycle.
const MAX_ISOLATED: usize = 64;

/// Default high watermark (number of free pages).
const DEFAULT_HIGH_WM: u64 = 512;

/// Default low watermark (number of free pages).
const DEFAULT_LOW_WM: u64 = 128;

/// Default min watermark (number of free pages).
const DEFAULT_MIN_WM: u64 = 32;

// -------------------------------------------------------------------
// LruPageState
// -------------------------------------------------------------------

/// State of a page within the LRU lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LruPageState {
    /// Page is on the active list (recently accessed).
    #[default]
    Active,
    /// Page is on the inactive list (candidate for reclaim).
    Inactive,
    /// Page has been isolated for reclaim processing.
    Isolated,
    /// Page is unevictable (locked, mlocked, etc.).
    Unevictable,
}

// -------------------------------------------------------------------
// LruPage
// -------------------------------------------------------------------

/// Metadata for a page tracked in the LRU lists.
#[derive(Debug, Clone, Copy)]
pub struct LruPage {
    /// Physical frame number.
    pub pfn: u64,
    /// Current LRU state.
    pub state: LruPageState,
    /// Whether the page has been accessed since last scan.
    pub referenced: bool,
    /// Whether the page is dirty (needs write-back).
    pub dirty: bool,
    /// Number of times the page has been accessed (aging counter).
    pub age: u8,
    /// Process that owns this page (0 = kernel).
    pub owner_pid: u64,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl LruPage {
    /// Creates an empty, inactive LRU page entry.
    const fn empty() -> Self {
        Self {
            pfn: 0,
            state: LruPageState::Active,
            referenced: false,
            dirty: false,
            age: 0,
            owner_pid: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// LruList
// -------------------------------------------------------------------

/// Dual-list LRU tracking active and inactive pages.
///
/// Pages start on the active list. When scanned and found
/// unreferenced, they are demoted to inactive. Inactive pages
/// that remain unreferenced are candidates for reclaim.
pub struct LruList {
    /// Page slots (flat array with state-based partitioning).
    pages: [LruPage; MAX_LRU_PAGES],
    /// Number of pages on the active list.
    active_count: usize,
    /// Number of pages on the inactive list.
    inactive_count: usize,
    /// Total occupied slots.
    total: usize,
}

impl Default for LruList {
    fn default() -> Self {
        Self::new()
    }
}

impl LruList {
    /// Creates a new empty LRU list.
    pub const fn new() -> Self {
        Self {
            pages: [LruPage::empty(); MAX_LRU_PAGES],
            active_count: 0,
            inactive_count: 0,
            total: 0,
        }
    }

    /// Adds a page to the active list.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all LRU slots are full.
    /// Returns [`Error::AlreadyExists`] if the PFN is already tracked.
    pub fn add_page(&mut self, pfn: u64, owner_pid: u64) -> Result<()> {
        // Check for duplicate.
        if self.find_index(pfn).is_some() {
            return Err(Error::AlreadyExists);
        }

        let slot = self
            .pages
            .iter_mut()
            .find(|p| !p.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = LruPage::empty();
        slot.pfn = pfn;
        slot.owner_pid = owner_pid;
        slot.state = LruPageState::Active;
        slot.referenced = true;
        slot.active = true;

        self.active_count += 1;
        self.total += 1;
        Ok(())
    }

    /// Removes a page from the LRU lists by PFN.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PFN is not tracked.
    pub fn remove_page(&mut self, pfn: u64) -> Result<()> {
        let idx = self.find_index(pfn).ok_or(Error::NotFound)?;
        let page = &mut self.pages[idx];

        match page.state {
            LruPageState::Active => {
                self.active_count = self.active_count.saturating_sub(1);
            }
            LruPageState::Inactive | LruPageState::Isolated => {
                self.inactive_count = self.inactive_count.saturating_sub(1);
            }
            LruPageState::Unevictable => {}
        }

        page.active = false;
        self.total = self.total.saturating_sub(1);
        Ok(())
    }

    /// Marks a page as referenced (accessed).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PFN is not tracked.
    pub fn mark_referenced(&mut self, pfn: u64) -> Result<()> {
        let idx = self.find_index(pfn).ok_or(Error::NotFound)?;
        self.pages[idx].referenced = true;
        Ok(())
    }

    /// Marks a page as dirty (needs write-back before reclaim).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PFN is not tracked.
    pub fn mark_dirty(&mut self, pfn: u64) -> Result<()> {
        let idx = self.find_index(pfn).ok_or(Error::NotFound)?;
        self.pages[idx].dirty = true;
        Ok(())
    }

    /// Promotes a page from inactive back to active.
    ///
    /// Called when a page on the inactive list is accessed again.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PFN is not tracked.
    /// Returns [`Error::InvalidArgument`] if the page is not
    /// inactive.
    pub fn activate(&mut self, pfn: u64) -> Result<()> {
        let idx = self.find_index(pfn).ok_or(Error::NotFound)?;
        let page = &mut self.pages[idx];
        if page.state != LruPageState::Inactive {
            return Err(Error::InvalidArgument);
        }
        page.state = LruPageState::Active;
        page.referenced = true;
        self.inactive_count = self.inactive_count.saturating_sub(1);
        self.active_count += 1;
        Ok(())
    }

    /// Demotes a page from active to inactive.
    ///
    /// Called during LRU scanning when an active page has not been
    /// referenced since the last scan.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PFN is not tracked.
    /// Returns [`Error::InvalidArgument`] if the page is not active.
    pub fn deactivate(&mut self, pfn: u64) -> Result<()> {
        let idx = self.find_index(pfn).ok_or(Error::NotFound)?;
        let page = &mut self.pages[idx];
        if page.state != LruPageState::Active {
            return Err(Error::InvalidArgument);
        }
        page.state = LruPageState::Inactive;
        page.referenced = false;
        self.active_count = self.active_count.saturating_sub(1);
        self.inactive_count += 1;
        Ok(())
    }

    /// Number of pages on the active list.
    pub const fn active_count(&self) -> usize {
        self.active_count
    }

    /// Number of pages on the inactive list.
    pub const fn inactive_count(&self) -> usize {
        self.inactive_count
    }

    /// Total pages tracked.
    pub const fn total(&self) -> usize {
        self.total
    }

    /// Returns `true` if no pages are tracked.
    pub const fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// Finds the index of a page by PFN.
    fn find_index(&self, pfn: u64) -> Option<usize> {
        self.pages.iter().position(|p| p.active && p.pfn == pfn)
    }
}

// -------------------------------------------------------------------
// ZoneWatermarks
// -------------------------------------------------------------------

/// Per-zone watermark thresholds controlling kswapd behavior.
///
/// - `min`: critical threshold — direct reclaim or OOM if below
/// - `low`: kswapd wakes and begins background reclaim
/// - `high`: kswapd stops reclaiming and goes back to sleep
#[derive(Debug, Clone, Copy)]
pub struct ZoneWatermarks {
    /// Zone identifier.
    pub zone_id: u8,
    /// Current number of free pages in this zone.
    pub free_pages: u64,
    /// Total pages in this zone.
    pub total_pages: u64,
    /// Minimum watermark (pages).
    pub min: u64,
    /// Low watermark (pages).
    pub low: u64,
    /// High watermark (pages).
    pub high: u64,
    /// Whether this zone is active.
    pub active: bool,
}

impl ZoneWatermarks {
    /// Creates a new zone with default watermarks.
    pub const fn new(zone_id: u8, total_pages: u64) -> Self {
        Self {
            zone_id,
            free_pages: total_pages,
            total_pages,
            min: DEFAULT_MIN_WM,
            low: DEFAULT_LOW_WM,
            high: DEFAULT_HIGH_WM,
            active: true,
        }
    }

    /// Creates an empty, inactive zone.
    const fn empty() -> Self {
        Self {
            zone_id: 0,
            free_pages: 0,
            total_pages: 0,
            min: 0,
            low: 0,
            high: 0,
            active: false,
        }
    }

    /// Returns `true` if free pages are below the low watermark.
    pub const fn below_low(&self) -> bool {
        self.free_pages < self.low
    }

    /// Returns `true` if free pages are below the min watermark.
    pub const fn below_min(&self) -> bool {
        self.free_pages < self.min
    }

    /// Returns `true` if free pages are above the high watermark.
    pub const fn above_high(&self) -> bool {
        self.free_pages >= self.high
    }

    /// Sets the watermarks to specific values.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the ordering
    /// `min <= low <= high` is violated.
    pub fn set_watermarks(&mut self, min: u64, low: u64, high: u64) -> Result<()> {
        if min > low || low > high {
            return Err(Error::InvalidArgument);
        }
        self.min = min;
        self.low = low;
        self.high = high;
        Ok(())
    }
}

// -------------------------------------------------------------------
// ScanCandidate
// -------------------------------------------------------------------

/// A page selected for possible reclaim during scanning.
#[derive(Debug, Clone, Copy)]
pub struct ScanCandidate {
    /// Physical frame number.
    pub pfn: u64,
    /// Whether the page is dirty.
    pub dirty: bool,
    /// Age counter at the time of isolation.
    pub age: u8,
    /// Owner PID.
    pub owner_pid: u64,
}

impl ScanCandidate {
    /// Creates an empty candidate.
    const fn empty() -> Self {
        Self {
            pfn: 0,
            dirty: false,
            age: 0,
            owner_pid: 0,
        }
    }
}

// -------------------------------------------------------------------
// PageScanner
// -------------------------------------------------------------------

/// Scans LRU lists to isolate reclaim candidates.
///
/// During each scan cycle, the scanner walks inactive pages, ages
/// them, and isolates those that have not been referenced. Dirty
/// pages are noted so the caller can schedule write-back before
/// freeing.
pub struct PageScanner {
    /// Isolated candidates from the last scan.
    candidates: [ScanCandidate; MAX_ISOLATED],
    /// Number of valid candidates.
    candidate_count: usize,
    /// Pages scanned in the last cycle.
    last_scanned: usize,
    /// Batch size for scanning.
    batch_size: usize,
}

impl Default for PageScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl PageScanner {
    /// Creates a new page scanner with default batch size.
    pub const fn new() -> Self {
        Self {
            candidates: [ScanCandidate::empty(); MAX_ISOLATED],
            candidate_count: 0,
            last_scanned: 0,
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }

    /// Sets the scan batch size.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `size` is zero.
    pub fn set_batch_size(&mut self, size: usize) -> Result<()> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        self.batch_size = size;
        Ok(())
    }

    /// Scans inactive pages from the LRU list and isolates
    /// reclaim candidates.
    ///
    /// Walks up to `batch_size` inactive pages. Unreferenced pages
    /// are moved to the isolated state and recorded as candidates.
    /// Referenced pages get their flag cleared (second chance).
    ///
    /// `priority` controls how aggressively we scan:
    /// - 0 = scan everything
    /// - 12 = scan only 1/(2^12) of pages
    ///
    /// Returns the number of candidates isolated.
    pub fn scan_inactive(&mut self, lru: &mut LruList, priority: u8) -> usize {
        self.candidate_count = 0;
        self.last_scanned = 0;

        let priority = if priority > MAX_SCAN_PRIORITY {
            MAX_SCAN_PRIORITY
        } else {
            priority
        };

        // Compute effective batch: at priority 0, scan full batch;
        // at priority 12, scan batch >> 12 (min 1).
        let effective_batch = if priority == 0 {
            self.batch_size
        } else {
            let reduced = self.batch_size >> (priority as usize);
            if reduced == 0 { 1 } else { reduced }
        };

        let mut scanned = 0usize;

        for page in &mut lru.pages {
            if scanned >= effective_batch {
                break;
            }
            if self.candidate_count >= MAX_ISOLATED {
                break;
            }
            if !page.active {
                continue;
            }
            if page.state != LruPageState::Inactive {
                continue;
            }

            scanned += 1;

            if page.referenced {
                // Second chance: clear referenced, give another
                // rotation.
                page.referenced = false;
                page.age = page.age.saturating_add(1);
                continue;
            }

            // Isolate this page for reclaim.
            page.state = LruPageState::Isolated;
            self.candidates[self.candidate_count] = ScanCandidate {
                pfn: page.pfn,
                dirty: page.dirty,
                age: page.age,
                owner_pid: page.owner_pid,
            };
            self.candidate_count += 1;
        }

        self.last_scanned = scanned;
        self.candidate_count
    }

    /// Scans active pages and demotes unreferenced ones to
    /// inactive.
    ///
    /// This shrinks the active list to feed the inactive list.
    /// `count` is the maximum number of pages to demote.
    ///
    /// Returns the number of pages actually demoted.
    pub fn shrink_active(&mut self, lru: &mut LruList, count: usize) -> usize {
        let mut demoted = 0usize;

        for page in &mut lru.pages {
            if demoted >= count {
                break;
            }
            if !page.active {
                continue;
            }
            if page.state != LruPageState::Active {
                continue;
            }
            if page.referenced {
                page.referenced = false;
                continue;
            }

            // Demote to inactive.
            page.state = LruPageState::Inactive;
            page.referenced = false;
            lru.active_count = lru.active_count.saturating_sub(1);
            lru.inactive_count += 1;
            demoted += 1;
        }

        demoted
    }

    /// Returns the candidates isolated in the last scan.
    pub fn candidates(&self) -> &[ScanCandidate] {
        &self.candidates[..self.candidate_count]
    }

    /// Number of candidates isolated in the last scan.
    pub const fn candidate_count(&self) -> usize {
        self.candidate_count
    }

    /// Number of pages scanned in the last cycle.
    pub const fn last_scanned(&self) -> usize {
        self.last_scanned
    }
}

// -------------------------------------------------------------------
// KswapdConfig
// -------------------------------------------------------------------

/// Tunable parameters for the kswapd daemon.
#[derive(Debug, Clone, Copy)]
pub struct KswapdConfig {
    /// Scan batch size (pages per scan cycle).
    pub batch_size: usize,
    /// Whether to reclaim clean pages only (skip dirty).
    pub clean_only: bool,
    /// Maximum priority (0 = most aggressive).
    pub max_priority: u8,
    /// Whether the daemon is enabled.
    pub enabled: bool,
}

impl Default for KswapdConfig {
    fn default() -> Self {
        Self {
            batch_size: DEFAULT_BATCH_SIZE,
            clean_only: false,
            max_priority: MAX_SCAN_PRIORITY,
            enabled: true,
        }
    }
}

// -------------------------------------------------------------------
// KswapdStats
// -------------------------------------------------------------------

/// Reclaim statistics tracked by kswapd.
#[derive(Debug, Clone, Copy, Default)]
pub struct KswapdStats {
    /// Total pages scanned since boot.
    pub pages_scanned: u64,
    /// Total pages successfully reclaimed.
    pub pages_reclaimed: u64,
    /// Total pages skipped (dirty when clean_only is set).
    pub pages_skipped: u64,
    /// Number of times kswapd was woken up.
    pub wakeup_count: u64,
    /// Number of scan cycles where no pages were reclaimed.
    pub empty_cycles: u64,
    /// Current scan priority.
    pub current_priority: u8,
    /// Last scan cycle result count.
    pub last_scan_isolated: usize,
}

// -------------------------------------------------------------------
// KswapdState
// -------------------------------------------------------------------

/// Operating state of the kswapd daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KswapdState {
    /// Daemon is sleeping, watermarks are satisfied.
    #[default]
    Sleeping,
    /// Daemon is actively scanning and reclaiming pages.
    Scanning,
    /// Daemon is in direct reclaim mode (urgent, below min).
    DirectReclaim,
}

// -------------------------------------------------------------------
// KswapdDaemon
// -------------------------------------------------------------------

/// The kswapd page reclaim daemon.
///
/// Manages LRU lists and zone watermarks. When free memory drops
/// below a zone's low watermark, the daemon wakes and scans pages
/// for reclaim. It escalates scan priority when reclaim progress
/// stalls, and sleeps again once the high watermark is restored.
pub struct KswapdDaemon {
    /// LRU page list.
    lru: LruList,
    /// Page scanner.
    scanner: PageScanner,
    /// Per-zone watermarks.
    zones: [ZoneWatermarks; MAX_ZONES],
    /// Number of active zones.
    zone_count: usize,
    /// Current operating state.
    state: KswapdState,
    /// Current scan priority (0 = most aggressive).
    priority: u8,
    /// Configuration.
    config: KswapdConfig,
    /// Statistics.
    stats: KswapdStats,
}

impl Default for KswapdDaemon {
    fn default() -> Self {
        Self::new()
    }
}

impl KswapdDaemon {
    /// Creates a new kswapd daemon instance.
    pub const fn new() -> Self {
        Self {
            lru: LruList::new(),
            scanner: PageScanner::new(),
            zones: [ZoneWatermarks::empty(); MAX_ZONES],
            zone_count: 0,
            state: KswapdState::Sleeping,
            priority: MAX_SCAN_PRIORITY,
            config: KswapdConfig {
                batch_size: DEFAULT_BATCH_SIZE,
                clean_only: false,
                max_priority: MAX_SCAN_PRIORITY,
                enabled: true,
            },
            stats: KswapdStats {
                pages_scanned: 0,
                pages_reclaimed: 0,
                pages_skipped: 0,
                wakeup_count: 0,
                empty_cycles: 0,
                current_priority: MAX_SCAN_PRIORITY,
                last_scan_isolated: 0,
            },
        }
    }

    /// Registers a memory zone with watermarks.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all zone slots are full.
    pub fn add_zone(&mut self, zone_id: u8, total_pages: u64) -> Result<()> {
        if self.zone_count >= MAX_ZONES {
            return Err(Error::OutOfMemory);
        }
        self.zones[self.zone_count] = ZoneWatermarks::new(zone_id, total_pages);
        self.zone_count += 1;
        Ok(())
    }

    /// Sets watermarks for a zone.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no zone with `zone_id` exists.
    /// Returns [`Error::InvalidArgument`] if the ordering is invalid.
    pub fn set_zone_watermarks(
        &mut self,
        zone_id: u8,
        min: u64,
        low: u64,
        high: u64,
    ) -> Result<()> {
        let zone = self.zones[..self.zone_count]
            .iter_mut()
            .find(|z| z.active && z.zone_id == zone_id)
            .ok_or(Error::NotFound)?;
        zone.set_watermarks(min, low, high)
    }

    /// Updates the free page count for a zone.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no zone with `zone_id` exists.
    pub fn update_zone_free(&mut self, zone_id: u8, free_pages: u64) -> Result<()> {
        let zone = self.zones[..self.zone_count]
            .iter_mut()
            .find(|z| z.active && z.zone_id == zone_id)
            .ok_or(Error::NotFound)?;
        zone.free_pages = free_pages;
        Ok(())
    }

    /// Adds a page to the LRU for tracking.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] or [`Error::AlreadyExists`].
    pub fn track_page(&mut self, pfn: u64, owner_pid: u64) -> Result<()> {
        self.lru.add_page(pfn, owner_pid)
    }

    /// Removes a page from LRU tracking.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the page is not tracked.
    pub fn untrack_page(&mut self, pfn: u64) -> Result<()> {
        self.lru.remove_page(pfn)
    }

    /// Records a page access (marks as referenced).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the page is not tracked.
    pub fn page_accessed(&mut self, pfn: u64) -> Result<()> {
        self.lru.mark_referenced(pfn)
    }

    /// Checks all zones and determines if kswapd needs to wake.
    ///
    /// Returns `true` if any zone is below its low watermark.
    pub fn needs_reclaim(&self) -> bool {
        self.zones[..self.zone_count]
            .iter()
            .any(|z| z.active && z.below_low())
    }

    /// Checks if any zone is in critical state (below min).
    pub fn needs_direct_reclaim(&self) -> bool {
        self.zones[..self.zone_count]
            .iter()
            .any(|z| z.active && z.below_min())
    }

    /// Checks if all zones are above their high watermark.
    pub fn all_zones_balanced(&self) -> bool {
        self.zones[..self.zone_count]
            .iter()
            .filter(|z| z.active)
            .all(|z| z.above_high())
    }

    /// Main balance routine: scan and reclaim pages for a zone.
    ///
    /// This is the core of the `balance_pgdat` algorithm. It
    /// adjusts scan priority based on reclaim success:
    /// - If no pages reclaimed, increase priority (more aggressive)
    /// - If pages reclaimed, maintain or decrease priority
    /// - Stop when all zones are above high watermark
    ///
    /// Returns the number of pages reclaimed in this cycle.
    pub fn balance_pgdat(&mut self) -> usize {
        if !self.config.enabled {
            return 0;
        }

        // Wake up.
        self.stats.wakeup_count += 1;
        self.state = KswapdState::Scanning;

        if self.needs_direct_reclaim() {
            self.state = KswapdState::DirectReclaim;
            self.priority = 0; // Maximum aggression.
        }

        let mut total_reclaimed = 0usize;

        // Run scan cycles, escalating priority if needed.
        let mut cycles = 0u8;
        while cycles <= self.config.max_priority {
            if self.all_zones_balanced() {
                break;
            }

            // Shrink active list to feed inactive.
            let demoted = self.scanner.shrink_active(&mut self.lru, 16);
            let _ = demoted; // Informational only.

            // Scan inactive list.
            let isolated = self.scanner.scan_inactive(&mut self.lru, self.priority);

            self.stats.pages_scanned += self.scanner.last_scanned() as u64;
            self.stats.last_scan_isolated = isolated;

            // "Reclaim" isolated candidates.
            let mut reclaimed_this_cycle = 0usize;
            for i in 0..self.scanner.candidate_count() {
                let candidate = self.scanner.candidates[i];

                if self.config.clean_only && candidate.dirty {
                    self.stats.pages_skipped += 1;
                    continue;
                }

                // Remove from LRU (simulates freeing the page).
                if self.lru.remove_page(candidate.pfn).is_ok() {
                    reclaimed_this_cycle += 1;
                }
            }

            total_reclaimed += reclaimed_this_cycle;
            self.stats.pages_reclaimed += reclaimed_this_cycle as u64;

            if reclaimed_this_cycle == 0 {
                self.stats.empty_cycles += 1;
                // Escalate priority.
                self.priority = self.priority.saturating_sub(1);
            } else if self.priority < self.config.max_priority {
                // Ease off if making progress.
                self.priority += 1;
            }

            cycles += 1;
        }

        self.stats.current_priority = self.priority;

        // Reset to sleeping if balanced.
        if self.all_zones_balanced() {
            self.state = KswapdState::Sleeping;
            self.priority = self.config.max_priority;
        }

        total_reclaimed
    }

    /// Sets the daemon configuration.
    pub fn set_config(&mut self, config: KswapdConfig) {
        self.config = config;
    }

    /// Returns the current daemon configuration.
    pub const fn config(&self) -> &KswapdConfig {
        &self.config
    }

    /// Returns the current operating state.
    pub const fn state(&self) -> KswapdState {
        self.state
    }

    /// Returns the current scan priority.
    pub const fn priority(&self) -> u8 {
        self.priority
    }

    /// Returns reclaim statistics.
    pub const fn stats(&self) -> &KswapdStats {
        &self.stats
    }

    /// Returns a reference to the LRU list.
    pub const fn lru(&self) -> &LruList {
        &self.lru
    }

    /// Returns the number of active zones.
    pub const fn zone_count(&self) -> usize {
        self.zone_count
    }

    /// Returns a reference to a zone by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range.
    pub fn zone(&self, index: usize) -> Result<&ZoneWatermarks> {
        if index >= self.zone_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.zones[index])
    }

    /// Returns the total number of pages tracked in the LRU.
    pub const fn tracked_pages(&self) -> usize {
        self.lru.total
    }

    /// Returns `true` if the daemon is currently sleeping.
    pub const fn is_sleeping(&self) -> bool {
        matches!(self.state, KswapdState::Sleeping)
    }
}
