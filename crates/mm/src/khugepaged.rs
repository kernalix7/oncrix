// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! khugepaged — background daemon for collapsing small pages into
//! transparent huge pages.
//!
//! Scans process address spaces for ranges of 512 contiguous 4 KiB
//! pages that can be collapsed into a single 2 MiB huge page. The
//! daemon runs periodically, controlled by tunables, and performs
//! the allocate-copy-remap sequence to promote eligible regions.
//!
//! # Architecture
//!
//! - [`CollapseResult`] — outcome of a collapse attempt
//! - [`MmSlot`] — per-mm_struct tracking entry
//! - [`ScanWindow`] — current scan position within an mm_slot
//! - [`KhugepageTunables`] — configurable scan parameters
//! - [`KhugepageStats`] — collapse and scan statistics
//! - [`KhugepageDaemon`] — main daemon state machine
//!
//! # Collapse Algorithm
//!
//! 1. **Scan**: Walk mm_slots looking for 2 MiB-aligned regions
//! 2. **Eligibility**: Check each of 512 small pages (present,
//!    non-pinned, same NUMA node, not recently faulted)
//! 3. **Allocate**: Obtain a free huge page frame
//! 4. **Copy**: Copy 512 small pages into the huge page
//! 5. **Remap**: Replace 512 PTEs with a single huge PTE
//! 6. **Free**: Release the 512 old small page frames
//!
//! Reference: Linux `mm/khugepaged.c`.

use oncrix_lib::{Error, Result};

// -- Constants

/// Number of small (4 KiB) pages per 2 MiB huge page.
const PAGES_PER_HUGE: usize = 512;

/// 2 MiB huge page size in bytes.
const HUGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;

/// 2 MiB alignment mask.
const HUGE_PAGE_ALIGN_MASK: u64 = HUGE_PAGE_SIZE - 1;

/// Standard page size in bytes.
const PAGE_SIZE: u64 = 4096;

/// Maximum number of mm_slots tracked by khugepaged.
const MAX_MM_SLOTS: usize = 128;

/// Maximum number of small-page descriptors per scan window.
const MAX_SCAN_PAGES: usize = PAGES_PER_HUGE;

/// Maximum number of collapse requests queued.
const MAX_COLLAPSE_QUEUE: usize = 32;

/// Default scan sleep interval in milliseconds.
const DEFAULT_SCAN_SLEEP_MS: u64 = 10_000;

/// Default number of pages to scan per wakeup.
const DEFAULT_PAGES_TO_SCAN: u64 = 4096;

/// Maximum pages to scan per wakeup.
const MAX_PAGES_TO_SCAN: u64 = 65536;

// -- CollapseResult

/// Outcome of a collapse attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CollapseResult {
    /// Successfully collapsed 512 pages into a huge page.
    Success,
    /// Region was not eligible for collapse.
    #[default]
    NotEligible,
    /// Could not allocate a huge page frame.
    AllocFailed,
    /// A page was pinned or on a wrong NUMA node.
    Blocked,
    /// Collapse was deferred to the next scan cycle.
    Deferred,
}

// -- PageEligibility

/// Eligibility status of a single page for collapse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PageEligibility {
    /// Page is eligible for collapse.
    #[default]
    Eligible,
    /// Page is not present (PTE absent).
    NotPresent,
    /// Page is pinned (e.g., DMA target).
    Pinned,
    /// Page is on a different NUMA node.
    WrongNode,
    /// Page was recently faulted (hot).
    RecentlyFaulted,
    /// Page is a swap entry.
    SwapEntry,
    /// Page is shared (mapped by multiple processes).
    Shared,
}

// -- SmallPageDesc

/// Descriptor for a small page within a scan window.
#[derive(Debug, Clone, Copy)]
pub struct SmallPageDesc {
    /// Physical frame number of the page.
    pub pfn: u64,
    /// Virtual address of the page.
    pub vaddr: u64,
    /// Eligibility status.
    pub eligibility: PageEligibility,
    /// NUMA node the page resides on.
    pub numa_node: u8,
    /// Whether the page is dirty.
    pub dirty: bool,
    /// Reference count.
    pub refcount: u32,
    /// Whether this descriptor is valid.
    pub valid: bool,
}

impl SmallPageDesc {
    const fn empty() -> Self {
        Self {
            pfn: 0,
            vaddr: 0,
            eligibility: PageEligibility::Eligible,
            numa_node: 0,
            dirty: false,
            refcount: 0,
            valid: false,
        }
    }
}

impl Default for SmallPageDesc {
    fn default() -> Self {
        Self::empty()
    }
}

// -- MmSlotState

/// Lifecycle state of an mm_slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MmSlotState {
    /// Slot is empty / not registered.
    #[default]
    Empty,
    /// Registered and eligible for scanning.
    Active,
    /// Currently being scanned.
    Scanning,
    /// Scan completed for this cycle.
    Scanned,
    /// Removed (process exited).
    Removed,
}

// -- MmSlot

/// Per-mm_struct tracking entry for khugepaged.
///
/// Each slot represents one process address space that has been
/// registered for huge page scanning (typically via
/// `madvise(MADV_HUGEPAGE)` or global THP policy).
#[derive(Debug, Clone, Copy)]
pub struct MmSlot {
    /// Process ID owning this mm.
    pub pid: u64,
    /// Base virtual address of the next scan window.
    pub scan_address: u64,
    /// End of the scannable region.
    pub scan_end: u64,
    /// Current slot state.
    pub state: MmSlotState,
    /// Number of successful collapses for this mm.
    pub collapses: u64,
    /// Number of scan passes over this mm.
    pub scan_passes: u64,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl MmSlot {
    const fn empty() -> Self {
        Self {
            pid: 0,
            scan_address: 0,
            scan_end: 0,
            state: MmSlotState::Empty,
            collapses: 0,
            scan_passes: 0,
            active: false,
        }
    }
}

impl Default for MmSlot {
    fn default() -> Self {
        Self::empty()
    }
}

// -- CollapseRequest

/// Queued request for a page collapse operation.
#[derive(Debug, Clone, Copy)]
pub struct CollapseRequest {
    /// mm_slot index that originated the request.
    pub mm_slot_idx: usize,
    /// Base virtual address (2 MiB-aligned) to collapse.
    pub vaddr: u64,
    /// Target NUMA node for the huge page allocation.
    pub numa_node: u8,
    /// Number of eligible pages found during scan.
    pub eligible_count: u32,
    /// Whether this request is pending.
    pub pending: bool,
    /// Result after processing.
    pub result: CollapseResult,
}

impl CollapseRequest {
    const fn empty() -> Self {
        Self {
            mm_slot_idx: 0,
            vaddr: 0,
            numa_node: 0,
            eligible_count: 0,
            pending: false,
            result: CollapseResult::NotEligible,
        }
    }
}

impl Default for CollapseRequest {
    fn default() -> Self {
        Self::empty()
    }
}

// -- KhugepageTunables

/// Configurable scan parameters for khugepaged.
///
/// These correspond to sysfs tunables under
/// `/sys/kernel/mm/transparent_hugepage/khugepaged/`.
#[derive(Debug, Clone, Copy)]
pub struct KhugepageTunables {
    /// Milliseconds between scan cycles.
    pub scan_sleep_ms: u64,
    /// Number of pages to scan per wakeup.
    pub pages_to_scan: u64,
    /// Maximum absent PTEs allowed in a collapse region.
    pub max_ptes_none: u32,
    /// Maximum shared pages in a collapse region.
    pub max_ptes_shared: u32,
    /// Maximum swap entries in a collapse region.
    pub max_ptes_swap: u32,
    /// Whether defragmentation is enabled for collapse.
    pub defrag: bool,
}

impl KhugepageTunables {
    /// Create tunables with default values.
    pub const fn new() -> Self {
        Self {
            scan_sleep_ms: DEFAULT_SCAN_SLEEP_MS,
            pages_to_scan: DEFAULT_PAGES_TO_SCAN,
            max_ptes_none: 0,
            max_ptes_shared: 0,
            max_ptes_swap: 0,
            defrag: true,
        }
    }
}

impl Default for KhugepageTunables {
    fn default() -> Self {
        Self::new()
    }
}

// -- KhugepageStats

/// Collapse and scan statistics for khugepaged.
#[derive(Debug, Clone, Copy, Default)]
pub struct KhugepageStats {
    /// Number of scan cycles completed.
    pub scan_cycles: u64,
    /// Total pages scanned.
    pub pages_scanned: u64,
    /// Number of successful collapses.
    pub collapses_success: u64,
    /// Number of failed collapse attempts.
    pub collapses_failed: u64,
    /// Number of alloc failures during collapse.
    pub alloc_failures: u64,
    /// Number of pages found not eligible.
    pub pages_not_eligible: u64,
    /// Number of regions deferred.
    pub deferred: u64,
    /// Total huge pages produced.
    pub huge_pages_produced: u64,
    /// Total small pages freed by collapse.
    pub small_pages_freed: u64,
    /// Number of mm_slots scanned.
    pub mm_slots_scanned: u64,
}

// -- ScanWindow

/// Current scan position and page descriptors within an mm_slot.
///
/// Tracks the 512 small pages that could be collapsed into one
/// huge page at the current scan address.
pub struct ScanWindow {
    /// Base address of the window (2 MiB-aligned).
    base_addr: u64,
    /// Small page descriptors.
    pages: [SmallPageDesc; MAX_SCAN_PAGES],
    /// Number of eligible pages.
    eligible_count: u32,
    /// Number of not-present pages (holes).
    holes: u32,
    /// Number of swap entries.
    swap_entries: u32,
    /// Number of shared pages.
    shared_pages: u32,
    /// Dominant NUMA node.
    dominant_node: u8,
    /// Whether the scan is complete.
    complete: bool,
}

impl ScanWindow {
    /// Create a new empty scan window.
    const fn new() -> Self {
        Self {
            base_addr: 0,
            pages: [const { SmallPageDesc::empty() }; MAX_SCAN_PAGES],
            eligible_count: 0,
            holes: 0,
            swap_entries: 0,
            shared_pages: 0,
            dominant_node: 0,
            complete: false,
        }
    }

    /// Reset the window for a new base address.
    pub fn reset(&mut self, base_addr: u64) {
        self.base_addr = base_addr;
        for page in &mut self.pages {
            *page = SmallPageDesc::empty();
        }
        self.eligible_count = 0;
        self.holes = 0;
        self.swap_entries = 0;
        self.shared_pages = 0;
        self.dominant_node = 0;
        self.complete = false;
    }

    /// Record a page descriptor at the given index within the window.
    pub fn set_page(&mut self, index: usize, desc: SmallPageDesc) -> Result<()> {
        if index >= MAX_SCAN_PAGES {
            return Err(Error::InvalidArgument);
        }
        self.pages[index] = desc;
        self.pages[index].valid = true;

        match desc.eligibility {
            PageEligibility::Eligible => {
                self.eligible_count += 1;
            }
            PageEligibility::NotPresent => {
                self.holes += 1;
            }
            PageEligibility::SwapEntry => {
                self.swap_entries += 1;
            }
            PageEligibility::Shared => {
                self.shared_pages += 1;
            }
            _ => {}
        }
        Ok(())
    }

    /// Check if the window is eligible for collapse given tunables.
    pub fn is_eligible(&self, tunables: &KhugepageTunables) -> bool {
        if self.holes > tunables.max_ptes_none {
            return false;
        }
        if self.swap_entries > tunables.max_ptes_swap {
            return false;
        }
        if self.shared_pages > tunables.max_ptes_shared {
            return false;
        }
        // Need at least half the pages eligible.
        self.eligible_count as usize > PAGES_PER_HUGE / 2
    }

    /// Return the base address.
    pub fn base_addr(&self) -> u64 {
        self.base_addr
    }

    /// Return the eligible page count.
    pub fn eligible_count(&self) -> u32 {
        self.eligible_count
    }
}

impl Default for ScanWindow {
    fn default() -> Self {
        Self::new()
    }
}

// -- KhugepageDaemon

/// khugepaged background collapse daemon.
///
/// Manages mm_slot registration, periodic scanning, and collapse
/// operations. The daemon is driven by explicit `scan_step()` calls
/// rather than running in a real thread (cooperative scheduling in
/// `no_std`).
pub struct KhugepageDaemon {
    /// Registered mm_slots.
    mm_slots: [MmSlot; MAX_MM_SLOTS],
    /// Number of active mm_slots.
    slot_count: usize,
    /// Index of the current mm_slot being scanned.
    current_slot: usize,
    /// Collapse request queue.
    collapse_queue: [CollapseRequest; MAX_COLLAPSE_QUEUE],
    /// Number of pending collapse requests.
    collapse_pending: usize,
    /// Scan window for the current region.
    scan_window: ScanWindow,
    /// Tunables.
    tunables: KhugepageTunables,
    /// Statistics.
    stats: KhugepageStats,
    /// Whether the daemon is enabled.
    enabled: bool,
    /// Simulated free huge page pool (frames available).
    free_huge_pages: u64,
    /// Pages scanned in the current cycle.
    pages_this_cycle: u64,
}

impl KhugepageDaemon {
    /// Create a new daemon with default tunables.
    pub const fn new() -> Self {
        Self {
            mm_slots: [const { MmSlot::empty() }; MAX_MM_SLOTS],
            slot_count: 0,
            current_slot: 0,
            collapse_queue: [const { CollapseRequest::empty() }; MAX_COLLAPSE_QUEUE],
            collapse_pending: 0,
            scan_window: ScanWindow::new(),
            tunables: KhugepageTunables::new(),
            stats: KhugepageStats {
                scan_cycles: 0,
                pages_scanned: 0,
                collapses_success: 0,
                collapses_failed: 0,
                alloc_failures: 0,
                pages_not_eligible: 0,
                deferred: 0,
                huge_pages_produced: 0,
                small_pages_freed: 0,
                mm_slots_scanned: 0,
            },
            enabled: false,
            free_huge_pages: 64,
            pages_this_cycle: 0,
        }
    }

    /// Enable the daemon.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the daemon.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Whether the daemon is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Update tunables.
    pub fn set_tunables(&mut self, tunables: KhugepageTunables) -> Result<()> {
        if tunables.pages_to_scan > MAX_PAGES_TO_SCAN {
            return Err(Error::InvalidArgument);
        }
        if tunables.scan_sleep_ms == 0 {
            return Err(Error::InvalidArgument);
        }
        self.tunables = tunables;
        Ok(())
    }

    /// Return the current tunables.
    pub fn tunables(&self) -> &KhugepageTunables {
        &self.tunables
    }

    /// Set the number of free huge pages available for collapse.
    pub fn set_free_huge_pages(&mut self, count: u64) {
        self.free_huge_pages = count;
    }

    // ── mm_slot management ──────────────────────────────────

    /// Register a process address space for scanning.
    ///
    /// `scan_start` and `scan_end` define the scannable region.
    pub fn register_mm(&mut self, pid: u64, scan_start: u64, scan_end: u64) -> Result<usize> {
        if self.slot_count >= MAX_MM_SLOTS {
            return Err(Error::OutOfMemory);
        }
        // Validate alignment.
        if scan_start & HUGE_PAGE_ALIGN_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        if scan_end <= scan_start {
            return Err(Error::InvalidArgument);
        }

        // Find a free slot.
        let idx = self
            .mm_slots
            .iter()
            .position(|s| !s.active)
            .ok_or(Error::OutOfMemory)?;

        self.mm_slots[idx] = MmSlot {
            pid,
            scan_address: scan_start,
            scan_end,
            state: MmSlotState::Active,
            collapses: 0,
            scan_passes: 0,
            active: true,
        };
        self.slot_count += 1;
        Ok(idx)
    }

    /// Unregister an mm_slot by index.
    pub fn unregister_mm(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_MM_SLOTS {
            return Err(Error::InvalidArgument);
        }
        if !self.mm_slots[idx].active {
            return Err(Error::NotFound);
        }
        self.mm_slots[idx].state = MmSlotState::Removed;
        self.mm_slots[idx].active = false;
        self.slot_count = self.slot_count.saturating_sub(1);
        Ok(())
    }

    /// Unregister an mm_slot by PID.
    pub fn unregister_mm_by_pid(&mut self, pid: u64) -> Result<()> {
        let idx = self
            .mm_slots
            .iter()
            .position(|s| s.active && s.pid == pid)
            .ok_or(Error::NotFound)?;
        self.unregister_mm(idx)
    }

    /// Return the number of registered mm_slots.
    pub fn slot_count(&self) -> usize {
        self.slot_count
    }

    /// Return mm_slot information by index.
    pub fn mm_slot(&self, idx: usize) -> Result<&MmSlot> {
        if idx >= MAX_MM_SLOTS {
            return Err(Error::InvalidArgument);
        }
        if !self.mm_slots[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&self.mm_slots[idx])
    }

    // ── Scan and collapse ───────────────────────────────────

    /// Perform one scan step.
    ///
    /// Advances the scanner through mm_slots, checking page
    /// eligibility and queueing collapse requests. Call this
    /// periodically from the scheduler (cooperative model).
    ///
    /// Returns the number of pages scanned in this step.
    pub fn scan_step(&mut self) -> Result<u64> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        if self.slot_count == 0 {
            return Ok(0);
        }

        // Find the next active slot.
        let start = self.current_slot;
        let mut found = false;
        let slot_idx;

        // Search from current position.
        let mut search_idx = start;
        for _ in 0..MAX_MM_SLOTS {
            if self.mm_slots[search_idx].active
                && self.mm_slots[search_idx].state != MmSlotState::Removed
            {
                found = true;
                break;
            }
            search_idx = (search_idx + 1) % MAX_MM_SLOTS;
        }

        if !found {
            return Ok(0);
        }
        slot_idx = search_idx;

        self.mm_slots[slot_idx].state = MmSlotState::Scanning;
        self.stats.mm_slots_scanned += 1;

        // Align the scan address.
        let scan_addr = self.mm_slots[slot_idx].scan_address & !HUGE_PAGE_ALIGN_MASK;
        let scan_end = self.mm_slots[slot_idx].scan_end;

        if scan_addr >= scan_end {
            // Wrap around to start.
            self.mm_slots[slot_idx].scan_address =
                self.mm_slots[slot_idx].scan_end - ((scan_end - scan_addr) & !HUGE_PAGE_ALIGN_MASK);
            self.mm_slots[slot_idx].scan_passes += 1;
            self.mm_slots[slot_idx].state = MmSlotState::Scanned;
            self.current_slot = (slot_idx + 1) % MAX_MM_SLOTS;
            return Ok(0);
        }

        // Scan pages in the window at scan_addr.
        self.scan_window.reset(scan_addr);
        let mut scanned = 0u64;

        for i in 0..PAGES_PER_HUGE {
            let page_addr = scan_addr + (i as u64) * PAGE_SIZE;

            // Simulate page eligibility check.
            let desc = SmallPageDesc {
                pfn: page_addr / PAGE_SIZE,
                vaddr: page_addr,
                eligibility: PageEligibility::Eligible,
                numa_node: 0,
                dirty: false,
                refcount: 1,
                valid: true,
            };
            // Ignore error — window is correctly sized.
            let _ = self.scan_window.set_page(i, desc);
            scanned += 1;
        }

        self.stats.pages_scanned += scanned;
        self.pages_this_cycle += scanned;

        // Check eligibility and queue collapse.
        if self.scan_window.is_eligible(&self.tunables) {
            self.queue_collapse(slot_idx, scan_addr)?;
        } else {
            self.stats.pages_not_eligible += 1;
        }

        // Advance scan address.
        self.mm_slots[slot_idx].scan_address = scan_addr + HUGE_PAGE_SIZE;
        self.mm_slots[slot_idx].state = MmSlotState::Active;

        // Check if we have scanned enough pages this cycle.
        if self.pages_this_cycle >= self.tunables.pages_to_scan {
            self.pages_this_cycle = 0;
            self.stats.scan_cycles += 1;
            self.current_slot = (slot_idx + 1) % MAX_MM_SLOTS;
        }

        Ok(scanned)
    }

    /// Queue a collapse request for the given region.
    fn queue_collapse(&mut self, mm_slot_idx: usize, vaddr: u64) -> Result<()> {
        if self.collapse_pending >= MAX_COLLAPSE_QUEUE {
            self.stats.deferred += 1;
            return Err(Error::Busy);
        }

        // Find a free queue slot.
        let idx = self
            .collapse_queue
            .iter()
            .position(|r| !r.pending)
            .ok_or(Error::Busy)?;

        self.collapse_queue[idx] = CollapseRequest {
            mm_slot_idx,
            vaddr,
            numa_node: self.scan_window.dominant_node,
            eligible_count: self.scan_window.eligible_count,
            pending: true,
            result: CollapseResult::NotEligible,
        };
        self.collapse_pending += 1;
        Ok(())
    }

    /// Process one pending collapse request.
    ///
    /// Performs the allocate-copy-remap sequence. Returns the
    /// result of the collapse attempt.
    pub fn process_collapse(&mut self) -> Result<CollapseResult> {
        if self.collapse_pending == 0 {
            return Ok(CollapseResult::NotEligible);
        }

        // Find the first pending request.
        let idx = self
            .collapse_queue
            .iter()
            .position(|r| r.pending)
            .ok_or(Error::NotFound)?;

        // Allocate a huge page.
        if self.free_huge_pages == 0 {
            self.collapse_queue[idx].result = CollapseResult::AllocFailed;
            self.collapse_queue[idx].pending = false;
            self.collapse_pending = self.collapse_pending.saturating_sub(1);
            self.stats.alloc_failures += 1;
            self.stats.collapses_failed += 1;
            return Ok(CollapseResult::AllocFailed);
        }

        // Consume a huge page.
        self.free_huge_pages -= 1;

        // Simulate copy + remap (success).
        self.collapse_queue[idx].result = CollapseResult::Success;
        self.collapse_queue[idx].pending = false;
        self.collapse_pending = self.collapse_pending.saturating_sub(1);

        // Update mm_slot statistics.
        let mm_idx = self.collapse_queue[idx].mm_slot_idx;
        if mm_idx < MAX_MM_SLOTS && self.mm_slots[mm_idx].active {
            self.mm_slots[mm_idx].collapses += 1;
        }

        self.stats.collapses_success += 1;
        self.stats.huge_pages_produced += 1;
        self.stats.small_pages_freed += PAGES_PER_HUGE as u64;

        Ok(CollapseResult::Success)
    }

    /// Return the number of pending collapse requests.
    pub fn collapse_pending(&self) -> usize {
        self.collapse_pending
    }

    /// Return daemon statistics.
    pub fn stats(&self) -> &KhugepageStats {
        &self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = KhugepageStats::default();
    }
}

impl Default for KhugepageDaemon {
    fn default() -> Self {
        Self::new()
    }
}
