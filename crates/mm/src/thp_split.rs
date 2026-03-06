// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Transparent huge page (THP) splitting.
//!
//! Splits compound 2 MiB transparent huge pages back into 512 base
//! 4 KiB pages. Splitting is required when:
//! - Part of a THP needs different protection flags.
//! - Memory pressure forces reclaim of individual sub-pages.
//! - A partial `munmap` or `mprotect` covers only part of a THP.
//! - The deferred split list is drained during compaction.
//!
//! # Key Types
//!
//! - [`ThpSplitReason`] — why a split was requested
//! - [`SplitState`] — lifecycle of a split operation
//! - [`ThpSplitEntry`] — metadata for one THP being split
//! - [`DeferredSplitList`] — list of THPs queued for deferred split
//! - [`ThpSplitter`] — engine that performs the actual split
//! - [`ThpSplitNodeStats`] — per-NUMA-node split statistics
//! - [`ThpSplitStats`] — global split statistics
//!
//! Reference: Linux `mm/huge_memory.c` (`split_huge_page`,
//! `deferred_split_scan`), `Documentation/admin-guide/mm/transhuge.rst`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard base page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// 2 MiB THP size.
const THP_SIZE: u64 = 2 * 1024 * 1024;

/// Number of base pages in one 2 MiB THP.
const PAGES_PER_THP: u64 = THP_SIZE / PAGE_SIZE; // 512

/// THP order (log2(512) = 9).
const THP_ORDER: u8 = 9;

/// Maximum THPs tracked for splitting.
const MAX_SPLIT_ENTRIES: usize = 128;

/// Maximum THPs on the deferred split list.
const MAX_DEFERRED_SPLIT: usize = 256;

/// Maximum NUMA nodes for per-node statistics.
const MAX_NUMA_NODES: usize = 8;

/// TLB flush batch threshold.
const TLB_FLUSH_BATCH: usize = 32;

// -------------------------------------------------------------------
// ThpSplitReason
// -------------------------------------------------------------------

/// Reason a THP split was requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThpSplitReason {
    /// Partial munmap of the THP range.
    #[default]
    PartialUnmap,
    /// Partial mprotect changing protection on sub-range.
    PartialMprotect,
    /// Memory pressure — reclaim needs individual pages.
    MemoryPressure,
    /// Migration of individual sub-pages.
    Migration,
    /// Page poisoning (hardware error on sub-page).
    HwPoison,
    /// Deferred split queue drain.
    DeferredDrain,
    /// THP debugging or tracing.
    Debug,
}

// -------------------------------------------------------------------
// SplitState
// -------------------------------------------------------------------

/// Lifecycle state of a THP split operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SplitState {
    /// Split has not yet begun.
    #[default]
    Pending,
    /// THP is frozen (refcount pinned, page locked).
    Frozen,
    /// Page table entries have been adjusted to base pages.
    PtesAdjusted,
    /// Compound page metadata has been decomposed.
    Decomposed,
    /// Split completed successfully.
    Completed,
    /// Split failed and was aborted.
    Failed,
    /// Split deferred for later processing.
    Deferred,
}

// -------------------------------------------------------------------
// ThpSplitEntry
// -------------------------------------------------------------------

/// Metadata for a single THP being split.
#[derive(Debug, Clone, Copy)]
pub struct ThpSplitEntry {
    /// PFN of the compound head page.
    pub head_pfn: u64,
    /// Virtual address of the THP mapping.
    pub vaddr: u64,
    /// Reason for the split.
    pub reason: ThpSplitReason,
    /// Current split state.
    pub state: SplitState,
    /// Reference count of the compound page at freeze time.
    pub refcount: u32,
    /// Number of PTEs that mapped this THP.
    pub mapcount: u32,
    /// NUMA node of the THP.
    pub node_id: u8,
    /// Whether this was a partially-mapped THP.
    pub partial_mapped: bool,
    /// Number of sub-pages that were individually mapped.
    pub sub_mapped_count: u32,
}

impl Default for ThpSplitEntry {
    fn default() -> Self {
        Self {
            head_pfn: 0,
            vaddr: 0,
            reason: ThpSplitReason::PartialUnmap,
            state: SplitState::Pending,
            refcount: 0,
            mapcount: 0,
            node_id: 0,
            partial_mapped: false,
            sub_mapped_count: 0,
        }
    }
}

// -------------------------------------------------------------------
// DeferredSplitList
// -------------------------------------------------------------------

/// List of THPs queued for deferred splitting.
///
/// THPs are added here when splitting cannot be done immediately
/// (e.g., the page is under writeback). The list is drained during
/// compaction or when memory pressure rises.
pub struct DeferredSplitList {
    /// Queued THP PFNs.
    pfns: [u64; MAX_DEFERRED_SPLIT],
    /// Number of entries.
    nr_entries: usize,
}

impl DeferredSplitList {
    /// Creates a new empty deferred split list.
    pub fn new() -> Self {
        Self {
            pfns: [0u64; MAX_DEFERRED_SPLIT],
            nr_entries: 0,
        }
    }

    /// Adds a THP head PFN to the deferred list.
    pub fn add(&mut self, head_pfn: u64) -> Result<()> {
        if self.nr_entries >= MAX_DEFERRED_SPLIT {
            return Err(Error::OutOfMemory);
        }
        // Avoid duplicates.
        for i in 0..self.nr_entries {
            if self.pfns[i] == head_pfn {
                return Ok(());
            }
        }
        self.pfns[self.nr_entries] = head_pfn;
        self.nr_entries += 1;
        Ok(())
    }

    /// Removes and returns the next THP PFN for splitting.
    pub fn pop(&mut self) -> Option<u64> {
        if self.nr_entries == 0 {
            return None;
        }
        self.nr_entries -= 1;
        Some(self.pfns[self.nr_entries])
    }

    /// Returns the number of deferred entries.
    pub fn len(&self) -> usize {
        self.nr_entries
    }

    /// Returns true if the list is empty.
    pub fn is_empty(&self) -> bool {
        self.nr_entries == 0
    }
}

// -------------------------------------------------------------------
// ThpSplitNodeStats
// -------------------------------------------------------------------

/// Per-NUMA-node THP split statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct ThpSplitNodeStats {
    /// Total splits completed on this node.
    pub splits_completed: u64,
    /// Total splits failed on this node.
    pub splits_failed: u64,
    /// Total splits deferred on this node.
    pub splits_deferred: u64,
    /// Total base pages produced by splits.
    pub pages_produced: u64,
}

// -------------------------------------------------------------------
// ThpSplitStats
// -------------------------------------------------------------------

/// Global THP split statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct ThpSplitStats {
    /// Total split operations attempted.
    pub total_splits: u64,
    /// Total splits completed successfully.
    pub splits_completed: u64,
    /// Total splits that failed.
    pub splits_failed: u64,
    /// Total splits deferred.
    pub splits_deferred: u64,
    /// Total base pages produced by all splits.
    pub pages_produced: u64,
    /// Total TLB flushes performed during splits.
    pub tlb_flushes: u64,
    /// Splits triggered by memory pressure.
    pub pressure_splits: u64,
    /// Splits triggered by partial unmap/mprotect.
    pub partial_splits: u64,
    /// Deferred split list drain operations.
    pub deferred_drains: u64,
}

// -------------------------------------------------------------------
// ThpSplitter
// -------------------------------------------------------------------

/// Engine that performs THP splitting operations.
///
/// Manages the split lifecycle: freeze the compound page, adjust
/// page table entries, decompose the compound metadata, and update
/// per-node statistics.
pub struct ThpSplitter {
    /// Active split entries.
    entries: [ThpSplitEntry; MAX_SPLIT_ENTRIES],
    /// Number of active entries.
    nr_entries: usize,
    /// Deferred split list.
    deferred: DeferredSplitList,
    /// Per-node statistics.
    node_stats: [ThpSplitNodeStats; MAX_NUMA_NODES],
    /// Global statistics.
    stats: ThpSplitStats,
    /// TLB flush counter for batching.
    tlb_pending: usize,
}

impl ThpSplitter {
    /// Creates a new THP splitter.
    pub fn new() -> Self {
        Self {
            entries: [const {
                ThpSplitEntry {
                    head_pfn: 0,
                    vaddr: 0,
                    reason: ThpSplitReason::PartialUnmap,
                    state: SplitState::Pending,
                    refcount: 0,
                    mapcount: 0,
                    node_id: 0,
                    partial_mapped: false,
                    sub_mapped_count: 0,
                }
            }; MAX_SPLIT_ENTRIES],
            nr_entries: 0,
            deferred: DeferredSplitList::new(),
            node_stats: [const {
                ThpSplitNodeStats {
                    splits_completed: 0,
                    splits_failed: 0,
                    splits_deferred: 0,
                    pages_produced: 0,
                }
            }; MAX_NUMA_NODES],
            stats: ThpSplitStats::default(),
            tlb_pending: 0,
        }
    }

    /// Returns global statistics.
    pub fn stats(&self) -> &ThpSplitStats {
        &self.stats
    }

    /// Returns per-node statistics.
    pub fn node_stats(&self, node_id: usize) -> Result<&ThpSplitNodeStats> {
        if node_id >= MAX_NUMA_NODES {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.node_stats[node_id])
    }

    /// Returns the deferred split list length.
    pub fn deferred_count(&self) -> usize {
        self.deferred.len()
    }

    /// Queues a THP for splitting.
    pub fn queue_split(
        &mut self,
        head_pfn: u64,
        vaddr: u64,
        reason: ThpSplitReason,
        refcount: u32,
        mapcount: u32,
        node_id: u8,
    ) -> Result<()> {
        if self.nr_entries >= MAX_SPLIT_ENTRIES {
            return Err(Error::Busy);
        }
        self.entries[self.nr_entries] = ThpSplitEntry {
            head_pfn,
            vaddr,
            reason,
            state: SplitState::Pending,
            refcount,
            mapcount,
            node_id,
            partial_mapped: false,
            sub_mapped_count: 0,
        };
        self.nr_entries += 1;
        self.stats.total_splits += 1;
        Ok(())
    }

    /// Attempts to freeze a compound page for splitting.
    ///
    /// Freezing pins the refcount and locks the page so that no
    /// concurrent access can modify its state during the split.
    fn freeze_page(entry: &mut ThpSplitEntry) -> Result<()> {
        if entry.refcount > 1 {
            // Cannot freeze if extra references exist beyond
            // the expected page cache + map references.
            // In async mode we defer instead of failing.
            return Err(Error::Busy);
        }
        entry.state = SplitState::Frozen;
        Ok(())
    }

    /// Adjusts page table entries from a single huge PTE to 512
    /// base PTEs pointing to each sub-page.
    fn adjust_ptes(entry: &mut ThpSplitEntry) {
        // Real implementation: for each VMA mapping this THP,
        // replace the PMD entry with a page table full of PTEs
        // pointing at head_pfn, head_pfn+1, ..., head_pfn+511.
        entry.state = SplitState::PtesAdjusted;
    }

    /// Decomposes the compound page metadata: clears compound
    /// head/tail flags on all 512 sub-pages.
    fn decompose_compound(entry: &mut ThpSplitEntry) {
        // Real implementation: for each tail page, clear
        // PageCompound and set individual refcounts.
        entry.state = SplitState::Decomposed;
    }

    /// Completes a single split operation and updates statistics.
    fn complete_split(&mut self, idx: usize) {
        let node = self.entries[idx].node_id as usize;
        self.entries[idx].state = SplitState::Completed;
        self.stats.splits_completed += 1;
        self.stats.pages_produced += PAGES_PER_THP;

        if self.entries[idx].reason == ThpSplitReason::MemoryPressure {
            self.stats.pressure_splits += 1;
        }
        if self.entries[idx].reason == ThpSplitReason::PartialUnmap
            || self.entries[idx].reason == ThpSplitReason::PartialMprotect
        {
            self.stats.partial_splits += 1;
        }

        if node < MAX_NUMA_NODES {
            self.node_stats[node].splits_completed += 1;
            self.node_stats[node].pages_produced += PAGES_PER_THP;
        }
    }

    /// Records a split failure and updates statistics.
    fn fail_split(&mut self, idx: usize) {
        let node = self.entries[idx].node_id as usize;
        self.entries[idx].state = SplitState::Failed;
        self.stats.splits_failed += 1;
        if node < MAX_NUMA_NODES {
            self.node_stats[node].splits_failed += 1;
        }
    }

    /// Defers a split entry to the deferred list.
    fn defer_split(&mut self, idx: usize) -> Result<()> {
        let pfn = self.entries[idx].head_pfn;
        self.entries[idx].state = SplitState::Deferred;
        self.deferred.add(pfn)?;
        self.stats.splits_deferred += 1;
        let node = self.entries[idx].node_id as usize;
        if node < MAX_NUMA_NODES {
            self.node_stats[node].splits_deferred += 1;
        }
        Ok(())
    }

    /// Flushes pending TLB invalidations.
    fn flush_tlb(&mut self) {
        if self.tlb_pending > 0 {
            self.stats.tlb_flushes += 1;
            self.tlb_pending = 0;
        }
    }

    /// Processes all queued split entries.
    ///
    /// Returns the number of THPs successfully split.
    pub fn process_splits(&mut self) -> Result<u64> {
        let mut completed = 0u64;
        let count = self.nr_entries;

        for i in 0..count {
            // Freeze.
            let freeze_ok = {
                let entry = &mut self.entries[i];
                Self::freeze_page(entry).is_ok()
            };

            if !freeze_ok {
                let _ = self.defer_split(i);
                continue;
            }

            // Adjust PTEs.
            Self::adjust_ptes(&mut self.entries[i]);

            // Queue TLB flush.
            self.tlb_pending += 1;
            if self.tlb_pending >= TLB_FLUSH_BATCH {
                self.flush_tlb();
            }

            // Decompose compound.
            Self::decompose_compound(&mut self.entries[i]);

            // Complete.
            self.complete_split(i);
            completed += 1;
        }

        // Final TLB flush.
        self.flush_tlb();
        self.nr_entries = 0;

        Ok(completed)
    }

    /// Drains the deferred split list under memory pressure.
    ///
    /// Attempts to split up to `max_splits` THPs from the deferred
    /// list. Returns the number of base pages freed.
    pub fn drain_deferred(&mut self, max_splits: usize) -> Result<u64> {
        let mut pages_freed = 0u64;
        let mut processed = 0usize;

        while processed < max_splits {
            let pfn = match self.deferred.pop() {
                Some(p) => p,
                None => break,
            };
            // Re-queue as active split entry.
            if self.nr_entries < MAX_SPLIT_ENTRIES {
                self.entries[self.nr_entries] = ThpSplitEntry {
                    head_pfn: pfn,
                    vaddr: 0,
                    reason: ThpSplitReason::DeferredDrain,
                    state: SplitState::Pending,
                    refcount: 0,
                    mapcount: 0,
                    node_id: 0,
                    partial_mapped: false,
                    sub_mapped_count: 0,
                };
                self.nr_entries += 1;
            }
            processed += 1;
        }

        if self.nr_entries > 0 {
            pages_freed = self.process_splits()? * PAGES_PER_THP;
        }

        self.stats.deferred_drains += 1;
        Ok(pages_freed)
    }

    /// Adds a THP to the deferred split list directly.
    pub fn defer_thp(&mut self, head_pfn: u64) -> Result<()> {
        self.deferred.add(head_pfn)
    }

    /// Returns the number of active split entries.
    pub fn active_count(&self) -> usize {
        self.nr_entries
    }
}
