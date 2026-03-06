// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Batch page reclaim operations.
//!
//! Implements scanning of LRU lists in configurable batches, collecting
//! reclaimable pages, submitting batch writeback, performing batch TLB
//! flushes, and driving reclaim via priority and watermark logic.
//!
//! # Key Types
//!
//! - [`ReclaimPriority`] — urgency level (0 = most urgent)
//! - [`PageReclaimState`] — per-page reclaim lifecycle
//! - [`ReclaimCandidate`] — a page selected for reclaim
//! - [`ReclaimBatch`] — a batch of candidates to process
//! - [`LruList`] — simple LRU list for inactive pages
//! - [`WritebackBatch`] — pages queued for writeback
//! - [`TlbFlushBatch`] — pages queued for TLB invalidation
//! - [`ReclaimWatermarks`] — thresholds driving reclaim urgency
//! - [`BatchReclaimer`] — the top-level reclaim engine
//! - [`ReclaimStats`] — cumulative statistics
//!
//! Reference: Linux `mm/vmscan.c` (`shrink_page_list`,
//! `shrink_lruvec`).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum pages in a single reclaim batch.
const MAX_BATCH_SIZE: usize = 64;

/// Maximum LRU list capacity.
const MAX_LRU_PAGES: usize = 2048;

/// Maximum writeback batch capacity.
const MAX_WRITEBACK_BATCH: usize = 32;

/// Maximum TLB flush batch capacity.
const MAX_TLB_FLUSH_BATCH: usize = 64;

/// Default scan batch size.
const DEFAULT_SCAN_BATCH: usize = 32;

/// Number of reclaim priority levels (0 = highest urgency).
const NR_PRIORITY_LEVELS: usize = 13;

/// Watermark fraction: reclaim starts below 1/4 of zone pages.
const RECLAIM_START_FRAC: u64 = 4;

/// Watermark fraction: reclaim stops above 3/8 of zone pages.
const RECLAIM_STOP_FRAC_NUM: u64 = 3;
const RECLAIM_STOP_FRAC_DEN: u64 = 8;

// -------------------------------------------------------------------
// ReclaimPriority
// -------------------------------------------------------------------

/// Reclaim priority level (0 = highest urgency, 12 = lowest).
///
/// Lower values scan more aggressively (smaller scan batch
/// divisor), while higher values are more conservative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReclaimPriority(pub u8);

impl ReclaimPriority {
    /// Most urgent priority.
    pub const HIGHEST: Self = Self(0);

    /// Default background reclaim priority.
    pub const DEFAULT: Self = Self(12);

    /// Returns the scan divisor: 2^priority.
    pub fn scan_divisor(self) -> u64 {
        1u64 << self.0.min(12)
    }

    /// Returns the number of pages to scan given a total LRU size.
    pub fn pages_to_scan(self, lru_size: usize) -> usize {
        let divisor = self.scan_divisor();
        ((lru_size as u64) / divisor).max(1) as usize
    }
}

impl Default for ReclaimPriority {
    fn default() -> Self {
        Self::DEFAULT
    }
}

// -------------------------------------------------------------------
// PageReclaimState
// -------------------------------------------------------------------

/// Per-page reclaim lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PageReclaimState {
    /// Page is on the LRU, not yet scanned.
    #[default]
    OnLru,
    /// Page has been selected as a reclaim candidate.
    Selected,
    /// Page is undergoing writeback.
    Writeback,
    /// Page writeback completed, ready for TLB flush.
    WritebackDone,
    /// Page TLB entry invalidated, ready for final free.
    TlbFlushed,
    /// Page has been reclaimed and freed.
    Reclaimed,
    /// Page was found to be unreclaimable (referenced, locked).
    Skipped,
}

// -------------------------------------------------------------------
// ReclaimCandidate
// -------------------------------------------------------------------

/// A page selected for reclaim.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReclaimCandidate {
    /// Physical frame number.
    pub pfn: u64,
    /// Whether this page is dirty and needs writeback.
    pub dirty: bool,
    /// Whether this page is mapped and needs TLB flush.
    pub mapped: bool,
    /// Whether the page has been recently referenced.
    pub referenced: bool,
    /// Current reclaim state.
    pub state: PageReclaimState,
    /// Number of mappings (for shared pages).
    pub map_count: u16,
}

// -------------------------------------------------------------------
// ReclaimBatch
// -------------------------------------------------------------------

/// A batch of reclaim candidates.
pub struct ReclaimBatch {
    /// Candidate entries.
    entries: [ReclaimCandidate; MAX_BATCH_SIZE],
    /// Number of valid entries.
    count: usize,
}

impl ReclaimBatch {
    /// Creates an empty batch.
    pub const fn new() -> Self {
        Self {
            entries: [ReclaimCandidate {
                pfn: 0,
                dirty: false,
                mapped: false,
                referenced: false,
                state: PageReclaimState::OnLru,
                map_count: 0,
            }; MAX_BATCH_SIZE],
            count: 0,
        }
    }

    /// Adds a candidate to the batch.
    pub fn push(&mut self, candidate: ReclaimCandidate) -> Result<()> {
        if self.count >= MAX_BATCH_SIZE {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = candidate;
        self.count += 1;
        Ok(())
    }

    /// Returns the number of candidates.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns `true` if the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Clears the batch.
    pub fn clear(&mut self) {
        self.count = 0;
    }
}

impl Default for ReclaimBatch {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// LruList
// -------------------------------------------------------------------

/// Simple LRU list for tracking inactive pages.
pub struct LruList {
    /// Page PFNs in LRU order (head = least recently used).
    pfns: [u64; MAX_LRU_PAGES],
    /// Dirty flag per page.
    dirty: [bool; MAX_LRU_PAGES],
    /// Mapped flag per page.
    mapped: [bool; MAX_LRU_PAGES],
    /// Referenced flag per page.
    referenced: [bool; MAX_LRU_PAGES],
    /// Number of valid entries.
    count: usize,
}

impl LruList {
    /// Creates an empty LRU list.
    pub const fn new() -> Self {
        Self {
            pfns: [0u64; MAX_LRU_PAGES],
            dirty: [false; MAX_LRU_PAGES],
            mapped: [false; MAX_LRU_PAGES],
            referenced: [false; MAX_LRU_PAGES],
            count: 0,
        }
    }

    /// Adds a page to the tail (most recently used).
    pub fn push_tail(&mut self, pfn: u64, dirty: bool, mapped: bool) -> Result<()> {
        if self.count >= MAX_LRU_PAGES {
            return Err(Error::OutOfMemory);
        }
        self.pfns[self.count] = pfn;
        self.dirty[self.count] = dirty;
        self.mapped[self.count] = mapped;
        self.referenced[self.count] = false;
        self.count += 1;
        Ok(())
    }

    /// Returns the number of pages on the list.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the list is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Marks a page as referenced by PFN.
    pub fn mark_referenced(&mut self, pfn: u64) {
        for i in 0..self.count {
            if self.pfns[i] == pfn {
                self.referenced[i] = true;
                return;
            }
        }
    }

    /// Removes a page by PFN.
    pub fn remove(&mut self, pfn: u64) -> bool {
        for i in 0..self.count {
            if self.pfns[i] == pfn {
                self.pfns[i] = self.pfns[self.count - 1];
                self.dirty[i] = self.dirty[self.count - 1];
                self.mapped[i] = self.mapped[self.count - 1];
                self.referenced[i] = self.referenced[self.count - 1];
                self.count -= 1;
                return true;
            }
        }
        false
    }

    /// Scans up to `batch_size` pages from the head (LRU end),
    /// returning candidates for reclaim.
    pub fn scan_batch(&mut self, batch_size: usize) -> ReclaimBatch {
        let mut batch = ReclaimBatch::new();
        let to_scan = batch_size.min(self.count).min(MAX_BATCH_SIZE);

        for i in 0..to_scan {
            let candidate = ReclaimCandidate {
                pfn: self.pfns[i],
                dirty: self.dirty[i],
                mapped: self.mapped[i],
                referenced: self.referenced[i],
                state: PageReclaimState::Selected,
                map_count: if self.mapped[i] { 1 } else { 0 },
            };
            let _ = batch.push(candidate);
        }

        batch
    }
}

impl Default for LruList {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// WritebackBatch
// -------------------------------------------------------------------

/// Batch of pages queued for writeback before reclaim.
pub struct WritebackBatch {
    /// PFNs of dirty pages to write back.
    pfns: [u64; MAX_WRITEBACK_BATCH],
    /// Number of valid entries.
    count: usize,
    /// Number of writeback completions.
    completed: usize,
}

impl WritebackBatch {
    /// Creates an empty writeback batch.
    pub const fn new() -> Self {
        Self {
            pfns: [0u64; MAX_WRITEBACK_BATCH],
            count: 0,
            completed: 0,
        }
    }

    /// Adds a dirty page PFN.
    pub fn add(&mut self, pfn: u64) -> Result<()> {
        if self.count >= MAX_WRITEBACK_BATCH {
            return Err(Error::OutOfMemory);
        }
        self.pfns[self.count] = pfn;
        self.count += 1;
        Ok(())
    }

    /// Simulates submission of all queued writebacks.
    /// Returns the number submitted.
    pub fn submit_all(&self) -> usize {
        self.count
    }

    /// Marks a page writeback as complete.
    pub fn complete_one(&mut self) {
        if self.completed < self.count {
            self.completed += 1;
        }
    }

    /// Returns `true` when all submitted writebacks are done.
    pub fn all_complete(&self) -> bool {
        self.completed >= self.count
    }

    /// Returns the number of pending writebacks.
    pub fn pending(&self) -> usize {
        self.count.saturating_sub(self.completed)
    }

    /// Clears the batch.
    pub fn clear(&mut self) {
        self.count = 0;
        self.completed = 0;
    }
}

impl Default for WritebackBatch {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// TlbFlushBatch
// -------------------------------------------------------------------

/// Batch of virtual addresses for deferred TLB flush.
pub struct TlbFlushBatch {
    /// PFNs whose TLB entries need flushing.
    pfns: [u64; MAX_TLB_FLUSH_BATCH],
    /// Number of valid entries.
    count: usize,
}

impl TlbFlushBatch {
    /// Creates an empty TLB flush batch.
    pub const fn new() -> Self {
        Self {
            pfns: [0u64; MAX_TLB_FLUSH_BATCH],
            count: 0,
        }
    }

    /// Adds a PFN to the flush batch.
    pub fn add(&mut self, pfn: u64) -> Result<()> {
        if self.count >= MAX_TLB_FLUSH_BATCH {
            return Err(Error::OutOfMemory);
        }
        self.pfns[self.count] = pfn;
        self.count += 1;
        Ok(())
    }

    /// Performs the batch TLB flush. Returns the number flushed.
    ///
    /// In a real implementation this would invoke architecture-
    /// specific TLB invalidation. Here we model it as a count.
    pub fn flush(&mut self) -> usize {
        let flushed = self.count;
        self.count = 0;
        flushed
    }

    /// Returns the number of pending flushes.
    pub fn pending(&self) -> usize {
        self.count
    }
}

impl Default for TlbFlushBatch {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// ReclaimWatermarks
// -------------------------------------------------------------------

/// Watermark thresholds that drive reclaim urgency.
#[derive(Debug, Clone, Copy)]
pub struct ReclaimWatermarks {
    /// Total zone pages.
    pub zone_pages: u64,
    /// Reclaim starts when free pages drop below this.
    pub start_reclaim: u64,
    /// Reclaim stops when free pages rise above this.
    pub stop_reclaim: u64,
    /// Emergency threshold: OOM below this.
    pub emergency: u64,
}

impl ReclaimWatermarks {
    /// Computes watermarks from zone total pages.
    pub fn from_zone_pages(total: u64) -> Self {
        Self {
            zone_pages: total,
            start_reclaim: total / RECLAIM_START_FRAC,
            stop_reclaim: total * RECLAIM_STOP_FRAC_NUM / RECLAIM_STOP_FRAC_DEN,
            emergency: total / 16,
        }
    }

    /// Returns `true` if reclaim should be triggered.
    pub fn should_reclaim(&self, free_pages: u64) -> bool {
        free_pages < self.start_reclaim
    }

    /// Returns `true` if reclaim has restored enough free memory.
    pub fn reclaim_satisfied(&self, free_pages: u64) -> bool {
        free_pages >= self.stop_reclaim
    }

    /// Returns `true` if free memory is critically low.
    pub fn is_emergency(&self, free_pages: u64) -> bool {
        free_pages < self.emergency
    }
}

impl Default for ReclaimWatermarks {
    fn default() -> Self {
        Self::from_zone_pages(0)
    }
}

// -------------------------------------------------------------------
// ReclaimStats
// -------------------------------------------------------------------

/// Cumulative reclaim statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReclaimStats {
    /// Total pages scanned.
    pub pages_scanned: u64,
    /// Total pages reclaimed.
    pub pages_reclaimed: u64,
    /// Pages skipped (referenced, locked, etc.).
    pub pages_skipped: u64,
    /// Pages written back before reclaim.
    pub pages_writeback: u64,
    /// TLB flushes performed.
    pub tlb_flushes: u64,
    /// Batch reclaim iterations.
    pub batch_iterations: u64,
    /// Priority escalations.
    pub priority_escalations: u64,
}

// -------------------------------------------------------------------
// BatchReclaimer
// -------------------------------------------------------------------

/// Top-level batch page reclaim engine.
///
/// Drives the reclaim loop: scan LRU in batches, select candidates,
/// perform writeback for dirty pages, batch-flush TLB entries, and
/// free reclaimed pages. Priority escalates when insufficient pages
/// are reclaimed.
pub struct BatchReclaimer {
    /// Inactive LRU list.
    lru: LruList,
    /// Current reclaim priority.
    priority: ReclaimPriority,
    /// Watermarks for reclaim decisions.
    watermarks: ReclaimWatermarks,
    /// Current zone free page count.
    free_pages: u64,
    /// Writeback batch.
    writeback: WritebackBatch,
    /// TLB flush batch.
    tlb_batch: TlbFlushBatch,
    /// Cumulative statistics.
    stats: ReclaimStats,
    /// Scan batch size.
    scan_batch_size: usize,
}

impl BatchReclaimer {
    /// Creates a new reclaimer for a zone.
    pub fn new(zone_pages: u64, free_pages: u64) -> Self {
        Self {
            lru: LruList::new(),
            priority: ReclaimPriority::DEFAULT,
            watermarks: ReclaimWatermarks::from_zone_pages(zone_pages),
            free_pages,
            writeback: WritebackBatch::new(),
            tlb_batch: TlbFlushBatch::new(),
            stats: ReclaimStats::default(),
            scan_batch_size: DEFAULT_SCAN_BATCH,
        }
    }

    /// Adds a page to the inactive LRU.
    pub fn add_to_lru(&mut self, pfn: u64, dirty: bool, mapped: bool) -> Result<()> {
        self.lru.push_tail(pfn, dirty, mapped)
    }

    /// Runs one reclaim iteration: scan, writeback, TLB flush, free.
    ///
    /// Returns the number of pages reclaimed in this iteration.
    pub fn reclaim_batch(&mut self) -> Result<usize> {
        if !self.watermarks.should_reclaim(self.free_pages) {
            return Ok(0);
        }

        let to_scan = self
            .priority
            .pages_to_scan(self.lru.len())
            .min(self.scan_batch_size);
        let batch = self.lru.scan_batch(to_scan);
        self.stats.pages_scanned += batch.count() as u64;

        let mut reclaimed = 0usize;

        // Phase 1: classify candidates.
        for i in 0..batch.count() {
            let candidate = batch.entries[i];

            // Skip referenced pages (give them a second chance).
            if candidate.referenced {
                self.stats.pages_skipped += 1;
                continue;
            }

            // Dirty pages need writeback.
            if candidate.dirty {
                let _ = self.writeback.add(candidate.pfn);
                continue;
            }

            // Mapped pages need TLB flush.
            if candidate.mapped {
                let _ = self.tlb_batch.add(candidate.pfn);
                continue;
            }

            // Clean, unmapped page: reclaim immediately.
            self.lru.remove(candidate.pfn);
            self.free_pages += 1;
            reclaimed += 1;
        }

        // Phase 2: submit writeback.
        let wb_submitted = self.writeback.submit_all();
        self.stats.pages_writeback += wb_submitted as u64;
        // Model writeback completion.
        for _ in 0..wb_submitted {
            self.writeback.complete_one();
        }
        self.writeback.clear();

        // Phase 3: batch TLB flush.
        let flushed = self.tlb_batch.flush();
        self.stats.tlb_flushes += flushed as u64;
        self.free_pages += flushed as u64;
        reclaimed += flushed;

        self.stats.pages_reclaimed += reclaimed as u64;
        self.stats.batch_iterations += 1;

        // Escalate priority if we did not reclaim enough.
        if reclaimed == 0 && self.priority.0 > 0 {
            self.priority = ReclaimPriority(self.priority.0 - 1);
            self.stats.priority_escalations += 1;
        }

        Ok(reclaimed)
    }

    /// Runs reclaim until the stop watermark is satisfied or
    /// priority reaches the highest level with no progress.
    pub fn reclaim_until_satisfied(&mut self) -> Result<u64> {
        let mut total_reclaimed = 0u64;

        for _ in 0..NR_PRIORITY_LEVELS {
            if self.watermarks.reclaim_satisfied(self.free_pages) {
                break;
            }
            let reclaimed = self.reclaim_batch()?;
            total_reclaimed += reclaimed as u64;

            if reclaimed == 0 && self.priority == ReclaimPriority::HIGHEST {
                break;
            }
        }

        Ok(total_reclaimed)
    }

    /// Returns current reclaim priority.
    pub fn priority(&self) -> ReclaimPriority {
        self.priority
    }

    /// Sets reclaim priority.
    pub fn set_priority(&mut self, priority: ReclaimPriority) {
        self.priority = priority;
    }

    /// Returns current free page count.
    pub fn free_pages(&self) -> u64 {
        self.free_pages
    }

    /// Returns a reference to the watermarks.
    pub fn watermarks(&self) -> &ReclaimWatermarks {
        &self.watermarks
    }

    /// Returns the LRU size.
    pub fn lru_size(&self) -> usize {
        self.lru.len()
    }

    /// Returns cumulative statistics.
    pub fn stats(&self) -> &ReclaimStats {
        &self.stats
    }

    /// Marks a page as referenced on the LRU.
    pub fn mark_referenced(&mut self, pfn: u64) {
        self.lru.mark_referenced(pfn);
    }

    /// Resets priority to default.
    pub fn reset_priority(&mut self) {
        self.priority = ReclaimPriority::DEFAULT;
    }
}
