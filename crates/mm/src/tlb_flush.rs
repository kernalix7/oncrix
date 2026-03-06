// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! TLB flush operations for the x86_64 architecture.
//!
//! Manages Translation Lookaside Buffer invalidation to maintain
//! coherence between page table updates and the processor's cached
//! translations. Supports single-page, range, full, and kernel-only
//! flushes, plus a per-CPU batching mechanism to amortise the cost
//! of frequent small invalidations.
//!
//! - [`TlbFlushType`] — category of flush operation
//! - [`TlbFlushEntry`] — a single pending flush in a batch
//! - [`TlbBatchFlush`] — per-CPU pending flush accumulator
//! - [`PcidState`] — PCID (Process-Context Identifier) tracking
//! - [`TlbFlushStats`] — aggregate flush statistics
//! - [`TlbFlushOps`] — the main TLB flush controller
//!
//! Reference: `.kernelORG/` — `arch/x86/mm/tlb.c`,
//! Intel SDM Vol. 3A §4.10 (Caching Translation Information).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum pages in a single batch flush before falling back to
/// full flush.
const MAX_BATCH_PAGES: usize = 64;

/// Maximum CPUs supported.
const MAX_CPUS: usize = 8;

/// Maximum PCID values (x86_64 supports 12-bit PCID → 4096).
const MAX_PCID: usize = 64;

/// Threshold: if a batch exceeds this many pages, do a full flush.
const FULL_FLUSH_THRESHOLD: usize = 48;

/// PCID feature flag bit.
const _PCID_FEATURE_BIT: u32 = 1 << 17;

/// INVPCID instruction support flag.
const _INVPCID_FEATURE_BIT: u32 = 1 << 10;

/// Lazy TLB mode: defer flushes until the CPU returns to
/// user-space.
const _LAZY_TLB_FLAG: u32 = 1 << 0;

// -------------------------------------------------------------------
// TlbFlushType
// -------------------------------------------------------------------

/// Category of TLB flush operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlbFlushType {
    /// Flush a single page.
    #[default]
    SinglePage,
    /// Flush a contiguous range of pages.
    Range,
    /// Flush the entire TLB (all translations).
    Full,
    /// Flush only kernel mappings.
    KernelOnly,
    /// Flush by PCID (invalidate all entries for a process).
    ByPcid,
}

// -------------------------------------------------------------------
// TlbFlushEntry
// -------------------------------------------------------------------

/// A single pending flush in a batch.
#[derive(Debug, Clone, Copy, Default)]
pub struct TlbFlushEntry {
    /// Virtual address of the page to flush.
    pub vaddr: u64,
    /// Number of contiguous pages (1 for single page).
    pub page_count: u32,
    /// Flush type.
    pub flush_type: TlbFlushType,
    /// Associated PCID (0 if not applicable).
    pub pcid: u16,
}

impl TlbFlushEntry {
    /// Creates a single-page flush entry.
    pub fn single(vaddr: u64) -> Self {
        Self {
            vaddr,
            page_count: 1,
            flush_type: TlbFlushType::SinglePage,
            pcid: 0,
        }
    }

    /// Creates a range flush entry.
    pub fn range(vaddr: u64, count: u32) -> Self {
        Self {
            vaddr,
            page_count: count,
            flush_type: TlbFlushType::Range,
            pcid: 0,
        }
    }
}

// -------------------------------------------------------------------
// TlbBatchFlush
// -------------------------------------------------------------------

/// Per-CPU pending flush accumulator.
///
/// Collects individual flush requests and either issues them as a
/// batch or falls back to a full flush when the batch is too large.
#[derive(Debug)]
pub struct TlbBatchFlush {
    /// Pending flush entries.
    entries: [TlbFlushEntry; MAX_BATCH_PAGES],
    /// Number of entries in the batch.
    count: usize,
    /// Whether a full flush is required (batch overflow).
    needs_full_flush: bool,
    /// CPU ID this batch belongs to.
    cpu_id: u32,
    /// Whether lazy TLB mode is active.
    lazy_mode: bool,
    /// Generation counter (incremented on each flush).
    generation: u64,
}

impl Default for TlbBatchFlush {
    fn default() -> Self {
        Self {
            entries: [TlbFlushEntry::default(); MAX_BATCH_PAGES],
            count: 0,
            needs_full_flush: false,
            cpu_id: 0,
            lazy_mode: false,
            generation: 0,
        }
    }
}

impl TlbBatchFlush {
    /// Creates a new batch for the given CPU.
    pub fn new(cpu_id: u32) -> Self {
        Self {
            cpu_id,
            ..Self::default()
        }
    }

    /// Adds a single page to the batch.
    pub fn add_page(&mut self, vaddr: u64) -> Result<()> {
        if self.count >= MAX_BATCH_PAGES {
            self.needs_full_flush = true;
            return Ok(());
        }
        self.entries[self.count] = TlbFlushEntry::single(vaddr);
        self.count += 1;
        if self.count >= FULL_FLUSH_THRESHOLD {
            self.needs_full_flush = true;
        }
        Ok(())
    }

    /// Adds a page range to the batch.
    pub fn add_range(&mut self, vaddr: u64, count: u32) -> Result<()> {
        if self.count >= MAX_BATCH_PAGES {
            self.needs_full_flush = true;
            return Ok(());
        }
        self.entries[self.count] = TlbFlushEntry::range(vaddr, count);
        self.count += 1;
        Ok(())
    }

    /// Returns the number of pending entries.
    pub fn pending_count(&self) -> usize {
        self.count
    }

    /// Returns `true` if the batch has overflowed.
    pub fn needs_full_flush(&self) -> bool {
        self.needs_full_flush
    }

    /// Returns `true` if no entries are pending.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Clears the batch (call after executing the flush).
    pub fn clear(&mut self) {
        self.count = 0;
        self.needs_full_flush = false;
        self.generation += 1;
    }

    /// Returns the CPU ID for this batch.
    pub fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Returns the current generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Enables lazy TLB mode.
    pub fn enable_lazy(&mut self) {
        self.lazy_mode = true;
    }

    /// Disables lazy TLB mode.
    pub fn disable_lazy(&mut self) {
        self.lazy_mode = false;
    }

    /// Returns `true` if lazy mode is active.
    pub fn is_lazy(&self) -> bool {
        self.lazy_mode
    }
}

// -------------------------------------------------------------------
// PcidState
// -------------------------------------------------------------------

/// Process-Context Identifier tracking.
///
/// PCID allows the TLB to hold translations for multiple address
/// spaces simultaneously. This structure tracks PCID allocation
/// and reuse.
#[derive(Debug)]
pub struct PcidState {
    /// Bitmap of allocated PCIDs (1 = in use).
    allocated: [bool; MAX_PCID],
    /// Next PCID to try allocating.
    next_free: usize,
    /// Total allocated count.
    allocated_count: usize,
    /// Whether PCID is supported by the hardware.
    pcid_supported: bool,
    /// Whether INVPCID instruction is available.
    invpcid_supported: bool,
    /// Generation counter for PCID rotation.
    generation: u64,
}

impl Default for PcidState {
    fn default() -> Self {
        Self {
            allocated: [false; MAX_PCID],
            next_free: 1, // PCID 0 is reserved for kernel
            allocated_count: 0,
            pcid_supported: false,
            invpcid_supported: false,
            generation: 0,
        }
    }
}

impl PcidState {
    /// Creates a new PCID state with hardware feature detection.
    pub fn new(pcid_supported: bool, invpcid_supported: bool) -> Self {
        Self {
            pcid_supported,
            invpcid_supported,
            ..Self::default()
        }
    }

    /// Allocates a new PCID, returning the value.
    pub fn allocate(&mut self) -> Result<u16> {
        if !self.pcid_supported {
            return Ok(0);
        }
        for i in 0..MAX_PCID {
            let idx = (self.next_free + i) % MAX_PCID;
            if idx == 0 {
                continue; // Reserved for kernel.
            }
            if !self.allocated[idx] {
                self.allocated[idx] = true;
                self.allocated_count += 1;
                self.next_free = (idx + 1) % MAX_PCID;
                return Ok(idx as u16);
            }
        }
        // All PCIDs exhausted — rotate generation and reclaim.
        self.generation += 1;
        self.flush_all_pcids();
        self.allocated[1] = true;
        self.allocated_count = 1;
        self.next_free = 2;
        Ok(1)
    }

    /// Releases a PCID back to the pool.
    pub fn release(&mut self, pcid: u16) -> Result<()> {
        let idx = pcid as usize;
        if idx == 0 || idx >= MAX_PCID {
            return Err(Error::InvalidArgument);
        }
        if !self.allocated[idx] {
            return Err(Error::NotFound);
        }
        self.allocated[idx] = false;
        self.allocated_count -= 1;
        Ok(())
    }

    /// Returns the number of allocated PCIDs.
    pub fn allocated_count(&self) -> usize {
        self.allocated_count
    }

    /// Returns the current generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Clears all PCID allocations (used on generation overflow).
    fn flush_all_pcids(&mut self) {
        for slot in self.allocated.iter_mut() {
            *slot = false;
        }
        self.allocated_count = 0;
    }
}

// -------------------------------------------------------------------
// TlbFlushStats
// -------------------------------------------------------------------

/// Aggregate TLB flush statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct TlbFlushStats {
    /// Total single-page flushes.
    pub single_flushes: u64,
    /// Total range flushes.
    pub range_flushes: u64,
    /// Total full flushes.
    pub full_flushes: u64,
    /// Total kernel-only flushes.
    pub kernel_flushes: u64,
    /// Total PCID-based flushes.
    pub pcid_flushes: u64,
    /// Total pages flushed (aggregate).
    pub total_pages_flushed: u64,
    /// Number of batch flushes executed.
    pub batch_flushes: u64,
    /// Number of batches that fell back to full flush.
    pub batch_overflows: u64,
    /// Lazy TLB activations.
    pub lazy_activations: u64,
}

impl TlbFlushStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// TlbFlushOps
// -------------------------------------------------------------------

/// Main TLB flush controller.
///
/// Manages per-CPU flush batches, PCID state, and flush statistics.
pub struct TlbFlushOps {
    /// Per-CPU flush batches.
    batches: [TlbBatchFlush; MAX_CPUS],
    /// PCID allocation state.
    pcid: PcidState,
    /// Aggregate statistics.
    stats: TlbFlushStats,
    /// Number of active CPUs.
    nr_cpus: usize,
}

impl Default for TlbFlushOps {
    fn default() -> Self {
        Self {
            batches: [const {
                TlbBatchFlush {
                    entries: [TlbFlushEntry {
                        vaddr: 0,
                        page_count: 0,
                        flush_type: TlbFlushType::SinglePage,
                        pcid: 0,
                    }; MAX_BATCH_PAGES],
                    count: 0,
                    needs_full_flush: false,
                    cpu_id: 0,
                    lazy_mode: false,
                    generation: 0,
                }
            }; MAX_CPUS],
            pcid: PcidState::default(),
            stats: TlbFlushStats::default(),
            nr_cpus: 1,
        }
    }
}

impl TlbFlushOps {
    /// Creates a new TLB flush controller.
    pub fn new(nr_cpus: usize) -> Self {
        let mut ops = Self::default();
        ops.nr_cpus = if nr_cpus > MAX_CPUS {
            MAX_CPUS
        } else if nr_cpus == 0 {
            1
        } else {
            nr_cpus
        };
        for i in 0..ops.nr_cpus {
            ops.batches[i].cpu_id = i as u32;
        }
        ops
    }

    /// Flushes the TLB entry for a single page on the current CPU.
    pub fn flush_page(&mut self, cpu: usize, vaddr: u64) -> Result<()> {
        if cpu >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }
        self.stats.single_flushes += 1;
        self.stats.total_pages_flushed += 1;

        // In a real kernel we would issue INVLPG here.
        // For now, record the flush in the batch if batching.
        if self.batches[cpu].is_lazy() {
            return self.batches[cpu].add_page(vaddr);
        }
        Ok(())
    }

    /// Flushes a range of pages on the current CPU.
    pub fn flush_range(&mut self, cpu: usize, start: u64, end: u64) -> Result<()> {
        if cpu >= self.nr_cpus || start >= end {
            return Err(Error::InvalidArgument);
        }
        let pages = (end - start) / PAGE_SIZE;
        self.stats.range_flushes += 1;
        self.stats.total_pages_flushed += pages;

        if self.batches[cpu].is_lazy() {
            return self.batches[cpu].add_range(start, pages as u32);
        }
        Ok(())
    }

    /// Performs a full TLB flush on the specified CPU.
    pub fn flush_all(&mut self, cpu: usize) -> Result<()> {
        if cpu >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }
        self.stats.full_flushes += 1;
        self.batches[cpu].clear();
        Ok(())
    }

    /// Flushes kernel-only TLB entries.
    pub fn flush_kernel(&mut self) -> Result<()> {
        self.stats.kernel_flushes += 1;
        Ok(())
    }

    /// Flushes TLB entries for a specific PCID.
    pub fn flush_by_pcid(&mut self, pcid: u16) -> Result<()> {
        if pcid as usize >= MAX_PCID {
            return Err(Error::InvalidArgument);
        }
        self.stats.pcid_flushes += 1;
        Ok(())
    }

    /// Executes all pending batched flushes on a CPU.
    pub fn flush_batch(&mut self, cpu: usize) -> Result<()> {
        if cpu >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }
        if self.batches[cpu].is_empty() {
            return Ok(());
        }

        self.stats.batch_flushes += 1;
        if self.batches[cpu].needs_full_flush() {
            self.stats.batch_overflows += 1;
            self.stats.full_flushes += 1;
        } else {
            let count = self.batches[cpu].pending_count();
            self.stats.total_pages_flushed += count as u64;
        }
        self.batches[cpu].clear();
        Ok(())
    }

    /// Enables lazy TLB mode on the specified CPU.
    pub fn enable_lazy(&mut self, cpu: usize) -> Result<()> {
        if cpu >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }
        self.batches[cpu].enable_lazy();
        self.stats.lazy_activations += 1;
        Ok(())
    }

    /// Disables lazy TLB mode and flushes pending entries.
    pub fn disable_lazy(&mut self, cpu: usize) -> Result<()> {
        if cpu >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }
        self.batches[cpu].disable_lazy();
        self.flush_batch(cpu)
    }

    /// Allocates a new PCID.
    pub fn allocate_pcid(&mut self) -> Result<u16> {
        self.pcid.allocate()
    }

    /// Releases a PCID.
    pub fn release_pcid(&mut self, pcid: u16) -> Result<()> {
        self.pcid.release(pcid)
    }

    /// Returns a reference to the statistics.
    pub fn stats(&self) -> &TlbFlushStats {
        &self.stats
    }

    /// Returns the batch state for a CPU.
    pub fn batch(&self, cpu: usize) -> Option<&TlbBatchFlush> {
        if cpu < self.nr_cpus {
            Some(&self.batches[cpu])
        } else {
            None
        }
    }

    /// Returns the number of active CPUs.
    pub fn nr_cpus(&self) -> usize {
        self.nr_cpus
    }

    /// Flushes all CPUs (full TLB flush).
    pub fn flush_all_cpus(&mut self) -> Result<()> {
        for cpu in 0..self.nr_cpus {
            self.batches[cpu].clear();
        }
        self.stats.full_flushes += self.nr_cpus as u64;
        Ok(())
    }

    /// Resets all statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
