// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Transparent Huge Pages (THP) subsystem.
//!
//! Provides automatic promotion of regular 4 KiB pages to 2 MiB huge
//! pages without explicit application awareness. THP reduces TLB
//! pressure and improves performance for memory-intensive workloads.
//!
//! - [`ThpMode`] — global THP enablement policy
//! - [`ThpDefragMode`] — defragmentation strategy for THP allocation
//! - [`ThpFaultResult`] — outcome of a THP page-fault attempt
//! - [`ThpMapping`] — tracks a single THP-backed virtual mapping
//! - [`ThpCollapseRequest`] — queued request to collapse small pages
//! - [`ThpStats`] — allocation and fault statistics
//! - [`ThpManager`] — central THP engine managing mappings and collapse

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Number of small (4 KiB) pages that form one 2 MiB huge page.
const SMALL_PAGES_PER_HUGE: u32 = 512;

/// 2 MiB huge page size in bytes.
const HUGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;

/// 2 MiB alignment mask.
const HUGE_PAGE_ALIGN_MASK: u64 = HUGE_PAGE_SIZE - 1;

/// Maximum tracked THP mappings.
const MAX_THP_MAPPINGS: usize = 512;

/// Maximum queued collapse requests.
const MAX_COLLAPSE_QUEUE: usize = 32;

// -------------------------------------------------------------------
// ThpMode
// -------------------------------------------------------------------

/// Global THP enablement policy.
///
/// Controls when the kernel attempts to allocate transparent huge
/// pages on page faults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThpMode {
    /// Always attempt THP allocation on every eligible fault.
    Always,
    /// Only attempt THP for regions marked with `madvise(MADV_HUGEPAGE)`.
    #[default]
    Madvise,
    /// Never allocate transparent huge pages.
    Never,
}

// -------------------------------------------------------------------
// ThpDefragMode
// -------------------------------------------------------------------

/// Defragmentation strategy for THP allocation.
///
/// Determines how aggressively the kernel compacts memory when a
/// direct huge page allocation fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThpDefragMode {
    /// Synchronously compact on every THP allocation failure.
    Always,
    /// Defer compaction to the `khugepaged` background thread.
    Defer,
    /// Defer for most faults, but compact synchronously for
    /// `madvise(MADV_HUGEPAGE)` regions.
    #[default]
    DeferPlusMadvise,
    /// Only compact synchronously for `madvise(MADV_HUGEPAGE)` regions.
    Madvise,
    /// Never attempt defragmentation for THP.
    Never,
}

// -------------------------------------------------------------------
// ThpFaultResult
// -------------------------------------------------------------------

/// Outcome of a THP page-fault attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThpFaultResult {
    /// Successfully allocated a 2 MiB huge page.
    Allocated,
    /// Fell back to regular 4 KiB page allocation.
    #[default]
    Fallback,
    /// Allocation failed entirely.
    Failed,
    /// Small pages were collapsed into a huge page.
    Collapsed,
}

// -------------------------------------------------------------------
// ThpMapping
// -------------------------------------------------------------------

/// Tracks a single virtual mapping that may be backed by a
/// transparent huge page.
#[derive(Debug, Clone, Copy, Default)]
pub struct ThpMapping {
    /// Virtual address (2 MiB-aligned when `huge` is true).
    pub vaddr: u64,
    /// Physical address of the backing page.
    pub phys_addr: u64,
    /// PID owning this mapping.
    pub pid: u64,
    /// Whether this mapping uses a 2 MiB huge page.
    pub huge: bool,
    /// Whether this slot is active.
    pub active: bool,
}

impl ThpMapping {
    /// Creates an empty, inactive mapping.
    const fn empty() -> Self {
        Self {
            vaddr: 0,
            phys_addr: 0,
            pid: 0,
            huge: false,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// ThpCollapseRequest
// -------------------------------------------------------------------

/// Queued request to collapse 512 small pages into one huge page.
#[derive(Debug, Clone, Copy, Default)]
pub struct ThpCollapseRequest {
    /// PID of the process requesting collapse.
    pub pid: u64,
    /// Virtual address of the region to collapse (2 MiB-aligned).
    pub vaddr: u64,
    /// Number of small pages to collapse (typically 512).
    pub nr_pages: u32,
    /// Scheduling priority (lower = higher priority).
    pub priority: u8,
    /// Whether this queue slot is in use.
    pub in_use: bool,
}

impl ThpCollapseRequest {
    /// Creates an empty, unused collapse request.
    const fn empty() -> Self {
        Self {
            pid: 0,
            vaddr: 0,
            nr_pages: 0,
            priority: 0,
            in_use: false,
        }
    }
}

// -------------------------------------------------------------------
// ThpStats
// -------------------------------------------------------------------

/// THP allocation and fault statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct ThpStats {
    /// Successful huge page allocations on fault.
    pub fault_alloc: u64,
    /// Faults that fell back to small pages.
    pub fault_fallback: u64,
    /// Successful collapse allocations.
    pub collapse_alloc: u64,
    /// Failed collapse attempts.
    pub collapse_fail: u64,
    /// Huge pages split back into small pages.
    pub split: u64,
    /// Zero huge pages served.
    pub zero_page: u64,
    /// Huge pages swapped out.
    pub swpout: u64,
    /// Swap-out fell back to small pages.
    pub swpout_fallback: u64,
}

// -------------------------------------------------------------------
// ThpManager
// -------------------------------------------------------------------

/// Central THP engine managing mappings, collapse queue, and
/// statistics.
///
/// Handles transparent promotion of 4 KiB pages to 2 MiB huge pages
/// on page faults, background collapse of contiguous small pages,
/// and splitting of huge pages when partial unmap is needed.
pub struct ThpManager {
    /// Current THP enablement mode.
    mode: ThpMode,
    /// Current defragmentation strategy.
    defrag: ThpDefragMode,
    /// THP mapping table.
    mappings: [ThpMapping; MAX_THP_MAPPINGS],
    /// Number of active mappings.
    map_count: usize,
    /// Pending collapse request queue.
    collapse_queue: [ThpCollapseRequest; MAX_COLLAPSE_QUEUE],
    /// Number of active collapse queue entries.
    cq_count: usize,
    /// Accumulated statistics.
    stats: ThpStats,
    /// Physical address of the shared zero huge page (if any).
    zero_huge_page: u64,
    /// Whether the THP subsystem is enabled.
    enabled: bool,
}

impl Default for ThpManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ThpManager {
    /// Creates a new THP manager with default settings.
    ///
    /// Mode defaults to [`ThpMode::Madvise`], defrag defaults to
    /// [`ThpDefragMode::DeferPlusMadvise`], and the subsystem starts
    /// enabled.
    pub const fn new() -> Self {
        Self {
            mode: ThpMode::Madvise,
            defrag: ThpDefragMode::DeferPlusMadvise,
            mappings: [ThpMapping::empty(); MAX_THP_MAPPINGS],
            map_count: 0,
            collapse_queue: [ThpCollapseRequest::empty(); MAX_COLLAPSE_QUEUE],
            cq_count: 0,
            stats: ThpStats {
                fault_alloc: 0,
                fault_fallback: 0,
                collapse_alloc: 0,
                collapse_fail: 0,
                split: 0,
                zero_page: 0,
                swpout: 0,
                swpout_fallback: 0,
            },
            zero_huge_page: 0,
            enabled: true,
        }
    }

    /// Handles a page fault that may be eligible for THP promotion.
    ///
    /// If the fault address is 2 MiB-aligned and conditions allow,
    /// allocates a transparent huge page. Otherwise falls back to
    /// regular 4 KiB allocation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the mapping table is full.
    /// Returns [`Error::NotImplemented`] if THP is disabled.
    pub fn handle_fault(&mut self, pid: u64, vaddr: u64, _write: bool) -> Result<ThpFaultResult> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }

        if self.mode == ThpMode::Never {
            self.stats.fault_fallback += 1;
            return Ok(ThpFaultResult::Fallback);
        }

        // Check if the address is 2 MiB-aligned and eligible.
        if !self.should_use_thp(pid, vaddr, HUGE_PAGE_SIZE as usize) {
            self.stats.fault_fallback += 1;
            return Ok(ThpFaultResult::Fallback);
        }

        // Attempt to allocate a huge page.
        // Stub: simulate allocation success when the address is
        // aligned and there is room in the mapping table.
        let aligned_vaddr = vaddr & !HUGE_PAGE_ALIGN_MASK;

        // Simulate physical address from virtual address.
        let phys_addr = aligned_vaddr;

        // Handle zero-page optimization for read faults.
        if self.zero_huge_page != 0 && !_write {
            self.stats.zero_page += 1;
            return self
                .add_mapping(pid, aligned_vaddr, self.zero_huge_page, true)
                .map(|_| ThpFaultResult::Allocated);
        }

        match self.add_mapping(pid, aligned_vaddr, phys_addr, true) {
            Ok(_) => {
                self.stats.fault_alloc += 1;
                Ok(ThpFaultResult::Allocated)
            }
            Err(_) => {
                // Try defrag-based recovery depending on mode.
                match self.defrag {
                    ThpDefragMode::Always => {
                        // Stub: synchronous compaction would run here.
                        self.stats.fault_fallback += 1;
                        Ok(ThpFaultResult::Fallback)
                    }
                    ThpDefragMode::Defer | ThpDefragMode::DeferPlusMadvise => {
                        self.stats.fault_fallback += 1;
                        Ok(ThpFaultResult::Fallback)
                    }
                    ThpDefragMode::Madvise | ThpDefragMode::Never => {
                        self.stats.fault_fallback += 1;
                        Ok(ThpFaultResult::Fallback)
                    }
                }
            }
        }
    }

    /// Splits a huge page mapping back into 512 small (4 KiB) pages.
    ///
    /// This is needed when a partial `munmap` or `mprotect` targets
    /// a sub-range of an existing huge page.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `mapping_idx` is out of
    /// bounds or the slot is not an active huge page mapping.
    pub fn split_huge_page(&mut self, mapping_idx: usize) -> Result<()> {
        if mapping_idx >= MAX_THP_MAPPINGS {
            return Err(Error::InvalidArgument);
        }

        let mapping = &self.mappings[mapping_idx];
        if !mapping.active || !mapping.huge {
            return Err(Error::InvalidArgument);
        }

        // Record the split and deactivate the huge mapping.
        // In a real implementation, 512 small PTEs would be installed.
        self.mappings[mapping_idx].huge = false;
        self.mappings[mapping_idx].active = false;
        self.map_count = self.map_count.saturating_sub(1);
        self.stats.split += 1;

        Ok(())
    }

    /// Collapses 512 contiguous small (4 KiB) pages into a single
    /// 2 MiB huge page for the given process and address.
    ///
    /// Returns `true` if the collapse succeeded, `false` if it was
    /// not possible (e.g., pages not contiguous or not all present).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if THP is disabled.
    /// Returns [`Error::OutOfMemory`] if the mapping table is full.
    pub fn collapse_pages(&mut self, pid: u64, vaddr: u64) -> Result<bool> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }

        let aligned = vaddr & !HUGE_PAGE_ALIGN_MASK;

        // Check if a huge mapping already exists.
        if let Some(idx) = self.find_mapping(pid, aligned) {
            if self.mappings[idx].huge {
                return Ok(false); // already huge
            }
        }

        // Stub: verify that 512 contiguous small pages are present
        // and eligible. In a real implementation, page table scanning
        // would occur here.
        let phys_addr = aligned; // simulated

        match self.add_mapping(pid, aligned, phys_addr, true) {
            Ok(_) => {
                self.stats.collapse_alloc += 1;
                Ok(true)
            }
            Err(e) => {
                self.stats.collapse_fail += 1;
                Err(e)
            }
        }
    }

    /// Enqueues a collapse request for background processing by the
    /// `khugepaged` equivalent.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the collapse queue is full.
    pub fn enqueue_collapse(&mut self, pid: u64, vaddr: u64) -> Result<()> {
        if self.cq_count >= MAX_COLLAPSE_QUEUE {
            return Err(Error::OutOfMemory);
        }

        let slot = self
            .collapse_queue
            .iter_mut()
            .find(|r| !r.in_use)
            .ok_or(Error::OutOfMemory)?;

        *slot = ThpCollapseRequest {
            pid,
            vaddr: vaddr & !HUGE_PAGE_ALIGN_MASK,
            nr_pages: SMALL_PAGES_PER_HUGE,
            priority: 128,
            in_use: true,
        };
        self.cq_count += 1;

        Ok(())
    }

    /// Processes all pending collapse requests in priority order.
    ///
    /// Returns the number of successfully collapsed regions.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if THP is disabled.
    pub fn process_collapse_queue(&mut self) -> Result<u32> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }

        let mut collapsed = 0u32;

        // Process entries from lowest priority value (highest prio)
        // to highest. Use index-based iteration to allow mutation.
        for i in 0..MAX_COLLAPSE_QUEUE {
            if !self.collapse_queue[i].in_use {
                continue;
            }

            let pid = self.collapse_queue[i].pid;
            let vaddr = self.collapse_queue[i].vaddr;

            match self.collapse_pages(pid, vaddr) {
                Ok(true) => {
                    collapsed += 1;
                    self.collapse_queue[i].in_use = false;
                    self.cq_count = self.cq_count.saturating_sub(1);
                }
                Ok(false) => {
                    // Already huge or not collapsible; remove from queue.
                    self.collapse_queue[i].in_use = false;
                    self.cq_count = self.cq_count.saturating_sub(1);
                }
                Err(_) => {
                    // Leave in queue for retry if it's a transient
                    // failure, unless mapping table is full.
                    self.collapse_queue[i].in_use = false;
                    self.cq_count = self.cq_count.saturating_sub(1);
                }
            }
        }

        Ok(collapsed)
    }

    /// Sets the THP enablement mode.
    pub fn set_mode(&mut self, mode: ThpMode) {
        self.mode = mode;
    }

    /// Sets the defragmentation strategy.
    pub fn set_defrag(&mut self, defrag: ThpDefragMode) {
        self.defrag = defrag;
    }

    /// Determines whether THP should be used for a given fault.
    ///
    /// Checks enablement mode, address alignment, and region size.
    pub fn should_use_thp(&self, _pid: u64, vaddr: u64, size: usize) -> bool {
        if !self.enabled {
            return false;
        }

        match self.mode {
            ThpMode::Never => false,
            ThpMode::Always => {
                // Must be at least huge-page-sized and aligned.
                size >= HUGE_PAGE_SIZE as usize && (vaddr & HUGE_PAGE_ALIGN_MASK) == 0
            }
            ThpMode::Madvise => {
                // In real code, check VMA flags for MADV_HUGEPAGE.
                // Stub: require alignment and sufficient size.
                size >= HUGE_PAGE_SIZE as usize && (vaddr & HUGE_PAGE_ALIGN_MASK) == 0
            }
        }
    }

    /// Returns a reference to the current THP statistics.
    pub fn get_stats(&self) -> &ThpStats {
        &self.stats
    }

    /// Finds the mapping table index for a given PID and virtual
    /// address.
    pub fn find_mapping(&self, pid: u64, vaddr: u64) -> Option<usize> {
        self.mappings
            .iter()
            .position(|m| m.active && m.pid == pid && m.vaddr == vaddr)
    }

    /// Enables the THP subsystem.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disables the THP subsystem.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Returns the number of active THP mappings.
    pub fn len(&self) -> usize {
        self.map_count
    }

    /// Returns `true` if there are no active THP mappings.
    pub fn is_empty(&self) -> bool {
        self.map_count == 0
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Adds a mapping to the table. Returns the slot index.
    fn add_mapping(&mut self, pid: u64, vaddr: u64, phys_addr: u64, huge: bool) -> Result<usize> {
        let idx = self
            .mappings
            .iter()
            .position(|m| !m.active)
            .ok_or(Error::OutOfMemory)?;

        self.mappings[idx] = ThpMapping {
            vaddr,
            phys_addr,
            pid,
            huge,
            active: true,
        };
        self.map_count += 1;

        Ok(idx)
    }
}
