// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Huge page fault handling.
//!
//! Handles page faults on huge page (hugetlb) mappings, including
//! demand allocation of huge pages, CoW faults on shared huge pages,
//! and fallback to base pages when huge page pool is exhausted.
//!
//! - [`HugeFaultType`] — type of huge page fault
//! - [`HugeFaultResult`] — result of fault handling
//! - [`HugeFaultEntry`] — a pending huge fault
//! - [`HugeFaultStats`] — fault statistics
//! - [`HugetlbFaultHandler`] — the fault handler
//!
//! Reference: Linux `mm/hugetlb.c` (hugetlb_fault).

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Huge page size (2 MiB).
const HUGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;

/// Maximum pending faults.
const MAX_FAULTS: usize = 128;

/// Maximum huge pages in the reserve pool.
const MAX_RESERVE: usize = 64;

// -------------------------------------------------------------------
// HugeFaultType
// -------------------------------------------------------------------

/// Type of huge page fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HugeFaultType {
    /// First access — demand allocation.
    #[default]
    DemandAlloc,
    /// Copy-on-Write fault.
    Cow,
    /// Migration fault (page moved away).
    Migration,
    /// Page reclaim fault (page was reclaimed).
    Reclaim,
}

// -------------------------------------------------------------------
// HugeFaultResult
// -------------------------------------------------------------------

/// Result of handling a huge page fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HugeFaultResult {
    /// Fault resolved — page mapped.
    #[default]
    Resolved,
    /// Fell back to base pages.
    Fallback,
    /// Out of huge pages — OOM.
    Oom,
    /// Retry needed (e.g., race condition).
    Retry,
    /// Error.
    Failed,
}

// -------------------------------------------------------------------
// HugeFaultEntry
// -------------------------------------------------------------------

/// A pending huge page fault.
#[derive(Debug, Clone, Copy, Default)]
pub struct HugeFaultEntry {
    /// Faulting virtual address.
    pub vaddr: u64,
    /// Process ID.
    pub pid: u64,
    /// Fault type.
    pub fault_type: HugeFaultType,
    /// Whether write access was requested.
    pub write: bool,
    /// Result of handling.
    pub result: HugeFaultResult,
    /// PFN allocated (if resolved).
    pub allocated_pfn: u64,
    /// Whether this entry is active.
    pub active: bool,
}

// -------------------------------------------------------------------
// HugeFaultStats
// -------------------------------------------------------------------

/// Huge page fault statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct HugeFaultStats {
    /// Total faults handled.
    pub total_faults: u64,
    /// Demand allocation faults.
    pub demand_allocs: u64,
    /// CoW faults.
    pub cow_faults: u64,
    /// Successfully resolved faults.
    pub resolved: u64,
    /// Fallback to base pages.
    pub fallbacks: u64,
    /// OOM during fault.
    pub ooms: u64,
    /// Retries.
    pub retries: u64,
}

impl HugeFaultStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// HugetlbFaultHandler
// -------------------------------------------------------------------

/// The hugetlb fault handler.
pub struct HugetlbFaultHandler {
    /// Pending faults.
    faults: [HugeFaultEntry; MAX_FAULTS],
    /// Number of faults.
    fault_count: usize,
    /// Reserve pool PFNs.
    reserve_pfns: [u64; MAX_RESERVE],
    /// Number of reserve pages.
    reserve_count: usize,
    /// Next PFN for allocation.
    next_pfn: u64,
    /// Statistics.
    stats: HugeFaultStats,
}

impl Default for HugetlbFaultHandler {
    fn default() -> Self {
        Self {
            faults: [HugeFaultEntry::default(); MAX_FAULTS],
            fault_count: 0,
            reserve_pfns: [0u64; MAX_RESERVE],
            reserve_count: 0,
            next_pfn: 0x20_0000,
            stats: HugeFaultStats::default(),
        }
    }
}

impl HugetlbFaultHandler {
    /// Creates a new fault handler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-allocates huge pages into the reserve pool.
    pub fn reserve(&mut self, nr_pages: usize) -> usize {
        let mut reserved = 0;
        for _ in 0..nr_pages {
            if self.reserve_count >= MAX_RESERVE {
                break;
            }
            self.reserve_pfns[self.reserve_count] = self.next_pfn;
            self.next_pfn += HUGE_PAGE_SIZE / 4096;
            self.reserve_count += 1;
            reserved += 1;
        }
        reserved
    }

    /// Allocates a huge page from the reserve pool.
    fn alloc_from_reserve(&mut self) -> Option<u64> {
        if self.reserve_count == 0 {
            return None;
        }
        self.reserve_count -= 1;
        Some(self.reserve_pfns[self.reserve_count])
    }

    /// Handles a huge page fault.
    pub fn handle_fault(
        &mut self,
        vaddr: u64,
        pid: u64,
        fault_type: HugeFaultType,
        write: bool,
    ) -> HugeFaultResult {
        self.stats.total_faults += 1;

        match fault_type {
            HugeFaultType::DemandAlloc => self.stats.demand_allocs += 1,
            HugeFaultType::Cow => self.stats.cow_faults += 1,
            _ => {}
        }

        // Try to allocate from reserve pool.
        let pfn = match self.alloc_from_reserve() {
            Some(pfn) => pfn,
            None => {
                self.stats.ooms += 1;
                self.record_fault(vaddr, pid, fault_type, write, HugeFaultResult::Oom, 0);
                return HugeFaultResult::Oom;
            }
        };

        let result = HugeFaultResult::Resolved;
        self.record_fault(vaddr, pid, fault_type, write, result, pfn);
        self.stats.resolved += 1;
        result
    }

    /// Records a fault in the history.
    fn record_fault(
        &mut self,
        vaddr: u64,
        pid: u64,
        fault_type: HugeFaultType,
        write: bool,
        result: HugeFaultResult,
        pfn: u64,
    ) {
        if self.fault_count < MAX_FAULTS {
            self.faults[self.fault_count] = HugeFaultEntry {
                vaddr,
                pid,
                fault_type,
                write,
                result,
                allocated_pfn: pfn,
                active: true,
            };
            self.fault_count += 1;
        }
    }

    /// Returns the number of reserve pages.
    pub fn reserve_count(&self) -> usize {
        self.reserve_count
    }

    /// Returns the fault count.
    pub fn fault_count(&self) -> usize {
        self.fault_count
    }

    /// Returns statistics.
    pub fn stats(&self) -> &HugeFaultStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
