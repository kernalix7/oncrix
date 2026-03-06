// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! TLB flush batching (mmu_gather).
//!
//! During page table teardown (munmap, process exit, mremap) the kernel
//! must invalidate TLB entries for every unmapped page. Issuing one
//! `invlpg` per page is extremely expensive when thousands of pages are
//! being freed. This module batches pages that need TLB invalidation
//! and flushes them in bulk, amortising the cost of TLB shootdown IPIs.
//!
//! # Design
//!
//! 1. The caller initialises an [`MmuGather`] context.
//! 2. As each page table entry is cleared, [`MmuGather::add_page`]
//!    records the page frame number and virtual address.
//! 3. When the batch is full or the caller explicitly calls
//!    [`MmuGather::flush`], a single TLB invalidation covers the
//!    entire range, and all collected frames are released to the frame
//!    allocator.
//! 4. [`MmuGather::finish`] performs a final flush and resets the
//!    context.
//!
//! # Flush granularity
//!
//! The module tracks whether individual `invlpg` instructions or a
//! full CR3 reload is more efficient based on the number of pages in
//! the batch. When the batch exceeds [`FULL_FLUSH_THRESHOLD`], a full
//! flush is issued instead of per-page invalidations.
//!
//! Reference: Linux `include/asm-generic/tlb.h`, `mm/mmu_gather.c`.

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────────────────

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of pages that can be batched before an automatic flush.
const MAX_BATCH_PAGES: usize = 512;

/// Threshold above which a full TLB flush (CR3 reload) is cheaper
/// than per-page `invlpg` instructions.
const FULL_FLUSH_THRESHOLD: usize = 64;

/// Maximum number of address ranges tracked per gather context.
const MAX_RANGES: usize = 16;

/// Maximum number of nested gather contexts (one per CPU would
/// suffice; 8 covers SMP scenarios).
const MAX_GATHER_CONTEXTS: usize = 8;

/// Huge page size (2 MiB).
const HUGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;

/// 1 GiB page size.
const GIGA_PAGE_SIZE: u64 = 1024 * 1024 * 1024;

// ── GatherState ─────────────────────────────────────────────────────────────

/// State of an [`MmuGather`] context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatherState {
    /// Context has been initialised but no pages added yet.
    Idle,
    /// Pages are being collected.
    Collecting,
    /// A flush is in progress.
    Flushing,
    /// The context has been finished and is ready for reuse.
    Finished,
}

impl Default for GatherState {
    fn default() -> Self {
        Self::Idle
    }
}

// ── PageSize ────────────────────────────────────────────────────────────────

/// Describes the size class of a page being gathered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageSize {
    /// Regular 4 KiB page.
    Regular,
    /// 2 MiB huge page.
    Huge,
    /// 1 GiB gigantic page.
    Giga,
}

impl PageSize {
    /// Returns the size in bytes.
    pub const fn bytes(self) -> u64 {
        match self {
            Self::Regular => PAGE_SIZE,
            Self::Huge => HUGE_PAGE_SIZE,
            Self::Giga => GIGA_PAGE_SIZE,
        }
    }
}

impl Default for PageSize {
    fn default() -> Self {
        Self::Regular
    }
}

// ── FlushRange ──────────────────────────────────────────────────────────────

/// A contiguous virtual address range that requires TLB invalidation.
///
/// The gather context merges adjacent pages into ranges so that
/// range-based TLB invalidation can be used where supported.
#[derive(Debug, Clone, Copy)]
pub struct FlushRange {
    /// Start virtual address (page-aligned).
    pub start: u64,
    /// End virtual address (exclusive, page-aligned).
    pub end: u64,
    /// Whether this range contains huge pages.
    pub has_huge_pages: bool,
    /// Number of individual pages in this range.
    pub page_count: u32,
    /// Whether this range slot is active.
    pub active: bool,
}

impl FlushRange {
    /// Creates an empty (inactive) range.
    const fn empty() -> Self {
        Self {
            start: 0,
            end: 0,
            has_huge_pages: false,
            page_count: 0,
            active: false,
        }
    }

    /// Returns the size of the range in bytes.
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Returns `true` if `addr` is adjacent to the end of this range.
    pub const fn is_adjacent(&self, addr: u64, page_size: u64) -> bool {
        self.active && self.end == addr && (self.end + page_size > self.end)
    }
}

// ── TlbBatch ────────────────────────────────────────────────────────────────

/// A batch of page frame numbers collected for deferred freeing.
///
/// When a TLB flush completes, all frames in the batch are released
/// back to the frame allocator in one go.
#[derive(Clone, Copy)]
pub struct TlbBatch {
    /// Page frame numbers pending release.
    pages: [u64; MAX_BATCH_PAGES],
    /// Corresponding page sizes.
    sizes: [PageSize; MAX_BATCH_PAGES],
    /// Number of pages in this batch.
    count: usize,
    /// Total bytes represented by pages in this batch.
    total_bytes: u64,
}

impl TlbBatch {
    /// Creates an empty batch.
    const fn new() -> Self {
        Self {
            pages: [0u64; MAX_BATCH_PAGES],
            sizes: [const { PageSize::Regular }; MAX_BATCH_PAGES],
            count: 0,
            total_bytes: 0,
        }
    }

    /// Returns `true` if the batch has reached capacity.
    pub const fn is_full(&self) -> bool {
        self.count >= MAX_BATCH_PAGES
    }

    /// Returns the number of pages in the batch.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Add a page to the batch.
    fn add(&mut self, pfn: u64, size: PageSize) -> Result<()> {
        if self.count >= MAX_BATCH_PAGES {
            return Err(Error::OutOfMemory);
        }
        self.pages[self.count] = pfn;
        self.sizes[self.count] = size;
        self.count += 1;
        self.total_bytes += size.bytes();
        Ok(())
    }

    /// Reset the batch for reuse.
    fn reset(&mut self) {
        self.count = 0;
        self.total_bytes = 0;
    }
}

// ── FlushMethod ─────────────────────────────────────────────────────────────

/// Describes how TLB invalidation should be performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushMethod {
    /// No flush needed (batch is empty).
    None,
    /// Invalidate individual pages via `invlpg`.
    PerPage,
    /// Full TLB flush via CR3 reload.
    FullFlush,
    /// Range-based invalidation (architecture-specific).
    RangeFlush,
}

// ── MmuGatherStats ──────────────────────────────────────────────────────────

/// Statistics for an [`MmuGather`] context.
#[derive(Debug, Clone, Copy)]
pub struct MmuGatherStats {
    /// Total pages gathered across all flushes.
    pub total_pages_gathered: u64,
    /// Total flush operations performed.
    pub total_flushes: u64,
    /// Number of full TLB flushes.
    pub full_flushes: u64,
    /// Number of per-page flushes.
    pub per_page_flushes: u64,
    /// Number of range-based flushes.
    pub range_flushes: u64,
    /// Total bytes freed.
    pub total_bytes_freed: u64,
    /// Peak batch size.
    pub peak_batch_size: usize,
}

impl MmuGatherStats {
    /// Creates zeroed statistics.
    const fn new() -> Self {
        Self {
            total_pages_gathered: 0,
            total_flushes: 0,
            full_flushes: 0,
            per_page_flushes: 0,
            range_flushes: 0,
            total_bytes_freed: 0,
            peak_batch_size: 0,
        }
    }
}

// ── MmuGather ───────────────────────────────────────────────────────────────

/// TLB flush batching context.
///
/// One context is used per teardown operation (e.g. one munmap call).
/// Pages are collected with [`MmuGather::add_page`] and flushed via
/// [`MmuGather::flush`] or automatically when the batch is full.
pub struct MmuGather {
    /// Current state of this context.
    state: GatherState,
    /// Page frame batch pending flush.
    batch: TlbBatch,
    /// Merged flush ranges.
    ranges: [FlushRange; MAX_RANGES],
    /// Number of active ranges.
    range_count: usize,
    /// Address space identifier (ASID / PCID).
    address_space_id: u64,
    /// Whether huge pages have been added to this batch.
    has_huge_pages: bool,
    /// Whether any page-table pages need to be freed.
    need_free_pt_pages: bool,
    /// Floor virtual address (lowest address seen).
    floor_addr: u64,
    /// Ceiling virtual address (highest end address seen).
    ceiling_addr: u64,
    /// Statistics for this context.
    stats: MmuGatherStats,
    /// Context identifier (for debugging / tracking).
    context_id: u32,
}

impl MmuGather {
    /// Creates an uninitialised context. Call [`MmuGather::init`] before use.
    pub const fn new() -> Self {
        Self {
            state: GatherState::Idle,
            batch: TlbBatch::new(),
            ranges: [const { FlushRange::empty() }; MAX_RANGES],
            range_count: 0,
            address_space_id: 0,
            has_huge_pages: false,
            need_free_pt_pages: false,
            floor_addr: u64::MAX,
            ceiling_addr: 0,
            stats: MmuGatherStats::new(),
            context_id: 0,
        }
    }

    /// Initialise the gather context for a specific address space.
    ///
    /// `asid` is the address space identifier (x86_64 PCID, ARM ASID).
    /// `context_id` is a caller-chosen tag for debugging.
    pub fn init(&mut self, asid: u64, context_id: u32) -> Result<()> {
        if self.state == GatherState::Collecting || self.state == GatherState::Flushing {
            return Err(Error::Busy);
        }
        self.state = GatherState::Idle;
        self.batch.reset();
        self.range_count = 0;
        for r in &mut self.ranges {
            *r = FlushRange::empty();
        }
        self.address_space_id = asid;
        self.has_huge_pages = false;
        self.need_free_pt_pages = false;
        self.floor_addr = u64::MAX;
        self.ceiling_addr = 0;
        self.stats = MmuGatherStats::new();
        self.context_id = context_id;
        Ok(())
    }

    /// Add a page to the batch for deferred TLB invalidation and freeing.
    ///
    /// `virt_addr` — virtual address of the page being unmapped.
    /// `pfn` — physical frame number.
    /// `size` — page size class.
    ///
    /// If the batch is full, an automatic flush is triggered before
    /// adding.
    pub fn add_page(&mut self, virt_addr: u64, pfn: u64, size: PageSize) -> Result<()> {
        if self.state == GatherState::Finished {
            return Err(Error::InvalidArgument);
        }

        // Auto-flush when batch is full.
        if self.batch.is_full() {
            self.flush()?;
        }

        self.state = GatherState::Collecting;
        self.batch.add(pfn, size)?;

        if size == PageSize::Huge || size == PageSize::Giga {
            self.has_huge_pages = true;
        }

        // Update floor / ceiling.
        if virt_addr < self.floor_addr {
            self.floor_addr = virt_addr;
        }
        let page_end = virt_addr.saturating_add(size.bytes());
        if page_end > self.ceiling_addr {
            self.ceiling_addr = page_end;
        }

        // Try to merge into an existing range.
        self.merge_or_add_range(virt_addr, size)?;

        self.stats.total_pages_gathered += 1;
        Ok(())
    }

    /// Flush the current batch: invalidate TLB entries and free pages.
    ///
    /// After flushing, the batch is reset and new pages can be added.
    pub fn flush(&mut self) -> Result<()> {
        if self.batch.count() == 0 {
            return Ok(());
        }

        self.state = GatherState::Flushing;

        let method = self.choose_flush_method();

        match method {
            FlushMethod::None => {}
            FlushMethod::PerPage => {
                self.flush_per_page()?;
                self.stats.per_page_flushes += 1;
            }
            FlushMethod::FullFlush => {
                self.flush_full()?;
                self.stats.full_flushes += 1;
            }
            FlushMethod::RangeFlush => {
                self.flush_ranges()?;
                self.stats.range_flushes += 1;
            }
        }

        // Record peak.
        if self.batch.count() > self.stats.peak_batch_size {
            self.stats.peak_batch_size = self.batch.count();
        }

        self.stats.total_flushes += 1;
        self.stats.total_bytes_freed += self.batch.total_bytes;

        // Free collected pages (stubbed — real implementation calls
        // the frame allocator).
        self.free_batch_pages()?;

        // Reset batch and ranges.
        self.batch.reset();
        self.range_count = 0;
        for r in &mut self.ranges {
            *r = FlushRange::empty();
        }
        self.has_huge_pages = false;

        self.state = GatherState::Collecting;
        Ok(())
    }

    /// Finish the gather context: flush remaining pages, then mark done.
    pub fn finish(&mut self) -> Result<()> {
        self.flush()?;
        self.state = GatherState::Finished;
        Ok(())
    }

    /// Returns `true` if there are unflushed pages in the batch.
    pub const fn needs_flush(&self) -> bool {
        self.batch.count() > 0
    }

    /// Returns the current state.
    pub const fn state(&self) -> GatherState {
        self.state
    }

    /// Returns a snapshot of statistics.
    pub const fn stats(&self) -> &MmuGatherStats {
        &self.stats
    }

    /// Returns the number of pages currently in the batch.
    pub const fn batch_count(&self) -> usize {
        self.batch.count()
    }

    /// Returns the address space identifier.
    pub const fn address_space_id(&self) -> u64 {
        self.address_space_id
    }

    /// Returns the virtual address floor (lowest seen address).
    pub const fn floor_addr(&self) -> u64 {
        self.floor_addr
    }

    /// Returns the virtual address ceiling (highest seen end address).
    pub const fn ceiling_addr(&self) -> u64 {
        self.ceiling_addr
    }

    /// Mark that page-table pages also need freeing after the flush.
    pub fn set_free_pt_pages(&mut self) {
        self.need_free_pt_pages = true;
    }

    /// Returns `true` if page-table pages need freeing.
    pub const fn needs_free_pt_pages(&self) -> bool {
        self.need_free_pt_pages
    }

    /// Returns the number of active flush ranges.
    pub const fn range_count(&self) -> usize {
        self.range_count
    }

    // ── Private helpers ─────────────────────────────────────────────

    /// Choose the best flush method based on batch size.
    fn choose_flush_method(&self) -> FlushMethod {
        let count = self.batch.count();
        if count == 0 {
            FlushMethod::None
        } else if count >= FULL_FLUSH_THRESHOLD {
            FlushMethod::FullFlush
        } else if self.range_count > 0 && self.range_count <= MAX_RANGES {
            FlushMethod::RangeFlush
        } else {
            FlushMethod::PerPage
        }
    }

    /// Stub: per-page `invlpg` invalidation.
    fn flush_per_page(&self) -> Result<()> {
        // In a real implementation, this would issue `invlpg` for
        // each page's virtual address via inline assembly.
        //
        // for each (virt_addr) in batch:
        //     asm!("invlpg [{}]", in(reg) virt_addr)
        Ok(())
    }

    /// Stub: full TLB flush via CR3 reload.
    fn flush_full(&self) -> Result<()> {
        // In a real implementation:
        //     let cr3 = read_cr3();
        //     asm!("mov cr3, {}", in(reg) cr3);
        // Plus IPI to other CPUs for shootdown.
        Ok(())
    }

    /// Stub: range-based TLB invalidation.
    fn flush_ranges(&self) -> Result<()> {
        // Issue `invlpg` in a loop over each range, or use
        // architecture-specific range invalidation.
        Ok(())
    }

    /// Stub: free all page frames in the batch.
    fn free_batch_pages(&self) -> Result<()> {
        // In a real implementation, each PFN in the batch would be
        // returned to the frame allocator.
        Ok(())
    }

    /// Merge `virt_addr` into an existing range or create a new one.
    fn merge_or_add_range(&mut self, virt_addr: u64, size: PageSize) -> Result<()> {
        let page_bytes = size.bytes();

        // Try to extend an existing range.
        for r in &mut self.ranges {
            if r.is_adjacent(virt_addr, page_bytes) {
                r.end = virt_addr.saturating_add(page_bytes);
                r.page_count += 1;
                if size != PageSize::Regular {
                    r.has_huge_pages = true;
                }
                return Ok(());
            }
        }

        // Create a new range if space is available.
        if self.range_count < MAX_RANGES {
            for r in &mut self.ranges {
                if !r.active {
                    r.start = virt_addr;
                    r.end = virt_addr.saturating_add(page_bytes);
                    r.has_huge_pages = size != PageSize::Regular;
                    r.page_count = 1;
                    r.active = true;
                    self.range_count += 1;
                    return Ok(());
                }
            }
        }

        // No space for a new range — ranges will be flushed on next
        // flush() anyway; this is not an error.
        Ok(())
    }
}

// ── MmuGatherPool ───────────────────────────────────────────────────────────

/// Pool of pre-allocated [`MmuGather`] contexts.
///
/// In the real kernel one context per CPU is sufficient. This pool
/// provides a small set that can be checked out and returned.
pub struct MmuGatherPool {
    /// Pre-allocated contexts.
    contexts: [MmuGather; MAX_GATHER_CONTEXTS],
    /// Bitmap: bit set = context is in use.
    in_use: u8,
}

impl MmuGatherPool {
    /// Creates a pool with all contexts available.
    pub const fn new() -> Self {
        Self {
            contexts: [const { MmuGather::new() }; MAX_GATHER_CONTEXTS],
            in_use: 0,
        }
    }

    /// Acquire a gather context.
    ///
    /// Returns the index into the pool on success.
    pub fn acquire(&mut self, asid: u64, context_id: u32) -> Result<usize> {
        for i in 0..MAX_GATHER_CONTEXTS {
            if self.in_use & (1 << i) == 0 {
                self.in_use |= 1 << i;
                self.contexts[i].init(asid, context_id)?;
                return Ok(i);
            }
        }
        Err(Error::Busy)
    }

    /// Get a mutable reference to an acquired context.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut MmuGather> {
        if index >= MAX_GATHER_CONTEXTS {
            return Err(Error::InvalidArgument);
        }
        if self.in_use & (1 << index) == 0 {
            return Err(Error::NotFound);
        }
        Ok(&mut self.contexts[index])
    }

    /// Release a context back to the pool.
    pub fn release(&mut self, index: usize) -> Result<()> {
        if index >= MAX_GATHER_CONTEXTS {
            return Err(Error::InvalidArgument);
        }
        if self.in_use & (1 << index) == 0 {
            return Err(Error::NotFound);
        }

        // Finish the context if it has pending pages.
        if self.contexts[index].needs_flush() {
            self.contexts[index].finish()?;
        }

        self.in_use &= !(1 << index);
        Ok(())
    }

    /// Returns the number of contexts currently in use.
    pub const fn active_count(&self) -> u32 {
        self.in_use.count_ones()
    }

    /// Returns `true` if all contexts are checked out.
    pub const fn is_full(&self) -> bool {
        self.in_use == u8::MAX >> (8 - MAX_GATHER_CONTEXTS as u32)
    }
}
