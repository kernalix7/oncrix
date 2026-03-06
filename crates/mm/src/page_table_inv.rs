// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page table invalidation and TLB shootdown.
//!
//! When page table entries are modified (unmap, permission change, CoW
//! break) the corresponding TLB entries on all CPUs that may have
//! cached the translation must be invalidated. This module implements
//! batched invalidation requests, inter-processor interrupt (IPI)
//! driven TLB shootdown, and lazy invalidation for single-threaded
//! address spaces.
//!
//! # Design
//!
//! ```text
//!  unmap_page(vaddr)
//!       → clear PTE
//!       → TlbInvalidator::invalidate(vaddr, size)
//!             │
//!             ├─ single CPU → invlpg(vaddr)
//!             ├─ multi CPU  → batch + IPI shootdown
//!             └─ full flush → cr3 reload
//! ```
//!
//! # Key Types
//!
//! - [`TlbInvRange`] — a range of addresses to invalidate
//! - [`TlbBatch`] — batched invalidation requests
//! - [`TlbInvalidator`] — the invalidation engine
//! - [`TlbShootdownStats`] — shootdown statistics
//!
//! Reference: Linux `arch/x86/mm/tlb.c`, `mm/mmu_gather.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum entries in an invalidation batch.
const MAX_BATCH_ENTRIES: usize = 128;

/// Page size.
const PAGE_SIZE: u64 = 4096;

/// Threshold: if more pages than this, do a full flush.
const FULL_FLUSH_THRESHOLD: usize = 64;

/// Maximum CPUs for shootdown targeting.
const MAX_CPUS: usize = 64;

// -------------------------------------------------------------------
// TlbInvType
// -------------------------------------------------------------------

/// Type of TLB invalidation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlbInvType {
    /// Invalidate a single page.
    SinglePage,
    /// Invalidate a range of pages.
    Range,
    /// Full TLB flush (reload CR3).
    FullFlush,
    /// Invalidate all non-global entries.
    AllNonGlobal,
}

impl TlbInvType {
    /// Return a label.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::SinglePage => "single_page",
            Self::Range => "range",
            Self::FullFlush => "full_flush",
            Self::AllNonGlobal => "all_non_global",
        }
    }
}

// -------------------------------------------------------------------
// TlbInvRange
// -------------------------------------------------------------------

/// A range of virtual addresses to invalidate.
#[derive(Debug, Clone, Copy)]
pub struct TlbInvRange {
    /// Start address (page-aligned).
    start: u64,
    /// End address (exclusive, page-aligned).
    end: u64,
    /// Whether to flush PTE caches too (PCID-aware).
    flush_pte: bool,
}

impl TlbInvRange {
    /// Create a new invalidation range.
    pub const fn new(start: u64, end: u64) -> Self {
        Self {
            start,
            end,
            flush_pte: false,
        }
    }

    /// Create a single-page invalidation.
    pub const fn single(addr: u64) -> Self {
        Self {
            start: addr,
            end: addr + PAGE_SIZE,
            flush_pte: false,
        }
    }

    /// Return the start address.
    pub const fn start(&self) -> u64 {
        self.start
    }

    /// Return the end address.
    pub const fn end(&self) -> u64 {
        self.end
    }

    /// Return the number of pages in the range.
    pub const fn nr_pages(&self) -> u64 {
        (self.end - self.start) / PAGE_SIZE
    }

    /// Check whether PTE caches should be flushed.
    pub const fn flush_pte(&self) -> bool {
        self.flush_pte
    }

    /// Enable PTE cache flush.
    pub fn set_flush_pte(&mut self) {
        self.flush_pte = true;
    }

    /// Check whether this range is a single page.
    pub const fn is_single_page(&self) -> bool {
        self.end - self.start == PAGE_SIZE
    }
}

impl Default for TlbInvRange {
    fn default() -> Self {
        Self {
            start: 0,
            end: 0,
            flush_pte: false,
        }
    }
}

// -------------------------------------------------------------------
// CpuMask
// -------------------------------------------------------------------

/// Bitmask of CPUs that need TLB shootdown.
#[derive(Debug, Clone, Copy)]
pub struct CpuMask {
    /// Bitmask (bit N = CPU N).
    bits: u64,
}

impl CpuMask {
    /// Empty mask.
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// All CPUs up to count.
    pub const fn all(count: u32) -> Self {
        if count >= 64 {
            Self { bits: u64::MAX }
        } else {
            Self {
                bits: (1u64 << count) - 1,
            }
        }
    }

    /// Set a CPU in the mask.
    pub fn set(&mut self, cpu: u32) {
        if (cpu as usize) < MAX_CPUS {
            self.bits |= 1u64 << cpu;
        }
    }

    /// Clear a CPU from the mask.
    pub fn clear(&mut self, cpu: u32) {
        if (cpu as usize) < MAX_CPUS {
            self.bits &= !(1u64 << cpu);
        }
    }

    /// Check whether a CPU is in the mask.
    pub const fn is_set(&self, cpu: u32) -> bool {
        if cpu >= 64 {
            return false;
        }
        self.bits & (1u64 << cpu) != 0
    }

    /// Return the number of CPUs set.
    pub const fn count(&self) -> u32 {
        self.bits.count_ones()
    }

    /// Check whether the mask is empty.
    pub const fn is_empty(&self) -> bool {
        self.bits == 0
    }
}

impl Default for CpuMask {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// TlbBatch
// -------------------------------------------------------------------

/// Batched TLB invalidation requests.
pub struct TlbBatch {
    /// Queued ranges.
    ranges: [TlbInvRange; MAX_BATCH_ENTRIES],
    /// Number of queued ranges.
    count: usize,
    /// Target CPUs.
    target_cpus: CpuMask,
    /// Whether a full flush is needed.
    full_flush: bool,
}

impl TlbBatch {
    /// Create a new empty batch.
    pub const fn new() -> Self {
        Self {
            ranges: [const {
                TlbInvRange {
                    start: 0,
                    end: 0,
                    flush_pte: false,
                }
            }; MAX_BATCH_ENTRIES],
            count: 0,
            target_cpus: CpuMask::empty(),
            full_flush: false,
        }
    }

    /// Return the number of queued entries.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Check whether a full flush is pending.
    pub const fn needs_full_flush(&self) -> bool {
        self.full_flush
    }

    /// Add a range to the batch.
    pub fn add(&mut self, range: TlbInvRange) -> Result<()> {
        if self.count >= MAX_BATCH_ENTRIES || self.full_flush {
            self.full_flush = true;
            return Ok(());
        }
        self.ranges[self.count] = range;
        self.count += 1;

        // Check if we should upgrade to full flush.
        let total_pages: u64 = self.ranges[..self.count].iter().map(|r| r.nr_pages()).sum();
        if (total_pages as usize) > FULL_FLUSH_THRESHOLD {
            self.full_flush = true;
        }
        Ok(())
    }

    /// Set the target CPUs.
    pub fn set_target_cpus(&mut self, mask: CpuMask) {
        self.target_cpus = mask;
    }

    /// Return the target CPU mask.
    pub const fn target_cpus(&self) -> &CpuMask {
        &self.target_cpus
    }

    /// Clear the batch.
    pub fn clear(&mut self) {
        self.count = 0;
        self.full_flush = false;
    }

    /// Determine the invalidation type for this batch.
    pub fn inv_type(&self) -> TlbInvType {
        if self.full_flush {
            TlbInvType::FullFlush
        } else if self.count == 1 && self.ranges[0].is_single_page() {
            TlbInvType::SinglePage
        } else {
            TlbInvType::Range
        }
    }
}

impl Default for TlbBatch {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// TlbShootdownStats
// -------------------------------------------------------------------

/// TLB shootdown statistics.
#[derive(Debug, Clone, Copy)]
pub struct TlbShootdownStats {
    /// Single page invalidations.
    pub single_inv: u64,
    /// Range invalidations.
    pub range_inv: u64,
    /// Full flushes.
    pub full_flushes: u64,
    /// IPI shootdowns sent.
    pub ipi_sent: u64,
    /// Total pages invalidated.
    pub pages_invalidated: u64,
}

impl TlbShootdownStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            single_inv: 0,
            range_inv: 0,
            full_flushes: 0,
            ipi_sent: 0,
            pages_invalidated: 0,
        }
    }
}

impl Default for TlbShootdownStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// TlbInvalidator
// -------------------------------------------------------------------

/// The TLB invalidation engine.
pub struct TlbInvalidator {
    /// Current batch.
    batch: TlbBatch,
    /// Statistics.
    stats: TlbShootdownStats,
    /// Number of online CPUs.
    nr_cpus: u32,
}

impl TlbInvalidator {
    /// Create a new invalidator.
    pub const fn new(nr_cpus: u32) -> Self {
        Self {
            batch: TlbBatch::new(),
            stats: TlbShootdownStats::new(),
            nr_cpus,
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &TlbShootdownStats {
        &self.stats
    }

    /// Queue an invalidation.
    pub fn invalidate(&mut self, start: u64, size: u64) -> Result<()> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        let range = TlbInvRange::new(start, start + size);
        self.batch.add(range)
    }

    /// Queue a single-page invalidation.
    pub fn invalidate_page(&mut self, addr: u64) -> Result<()> {
        let range = TlbInvRange::single(addr);
        self.batch.add(range)
    }

    /// Flush the batch — perform all queued invalidations.
    pub fn flush(&mut self) -> TlbInvType {
        let inv_type = self.batch.inv_type();
        match inv_type {
            TlbInvType::SinglePage => {
                self.stats.single_inv += 1;
                self.stats.pages_invalidated += 1;
            }
            TlbInvType::Range => {
                self.stats.range_inv += 1;
                let total: u64 = self.batch.ranges[..self.batch.count]
                    .iter()
                    .map(|r| r.nr_pages())
                    .sum();
                self.stats.pages_invalidated += total;
            }
            TlbInvType::FullFlush | TlbInvType::AllNonGlobal => {
                self.stats.full_flushes += 1;
            }
        }

        if self.nr_cpus > 1 {
            self.stats.ipi_sent += (self.nr_cpus - 1) as u64;
        }

        self.batch.clear();
        inv_type
    }

    /// Queue a full TLB flush.
    pub fn flush_all(&mut self) {
        self.batch.full_flush = true;
        self.flush();
    }
}

impl Default for TlbInvalidator {
    fn default() -> Self {
        Self::new(1)
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Invalidate a single page on the local CPU.
pub fn invlpg(addr: u64) -> TlbInvRange {
    TlbInvRange::single(addr)
}

/// Check whether a batch warrants full flush.
pub fn should_full_flush(nr_pages: usize) -> bool {
    nr_pages > FULL_FLUSH_THRESHOLD
}

/// Return the full flush threshold.
pub const fn full_flush_threshold() -> usize {
    FULL_FLUSH_THRESHOLD
}
