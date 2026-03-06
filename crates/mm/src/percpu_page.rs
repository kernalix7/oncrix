// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-CPU page allocation.
//!
//! Hot-path page allocations (page fault, slab refill) benefit from
//! per-CPU page lists that avoid global lock contention. Each CPU
//! maintains a small cache of free pages; allocations drain from the
//! local list and frees return pages to it. When the local list is
//! empty, a batch is refilled from the global allocator.
//!
//! # Design
//!
//! ```text
//!  alloc_page() on CPU N
//!     │
//!     ├─ percpu_list[N] not empty → pop page (lock-free)
//!     └─ empty → refill batch from buddy allocator
//!
//!  free_page() on CPU N
//!     │
//!     ├─ percpu_list[N] not full → push page
//!     └─ full → drain batch to buddy allocator
//! ```
//!
//! # Key Types
//!
//! - [`PerCpuPageList`] — per-CPU free page list
//! - [`PerCpuPageAllocator`] — manages all per-CPU lists
//! - [`PerCpuPageStats`] — allocation statistics
//!
//! Reference: Linux `mm/page_alloc.c` (per-cpu page lists, PCP).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum CPUs.
const MAX_CPUS: usize = 256;

/// Default per-CPU list capacity.
const DEFAULT_CAPACITY: usize = 128;

/// Batch size for refill/drain.
const BATCH_SIZE: usize = 32;

/// Page size.
const PAGE_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// PerCpuPageList
// -------------------------------------------------------------------

/// Per-CPU free page list.
#[derive(Debug, Clone, Copy)]
pub struct PerCpuPageList {
    /// CPU ID.
    cpu_id: u32,
    /// Free page PFNs.
    pages: [u64; DEFAULT_CAPACITY],
    /// Number of pages in list.
    count: usize,
    /// High watermark (drain threshold).
    high: usize,
    /// Low watermark (refill threshold).
    low: usize,
    /// Total allocations from this CPU.
    alloc_count: u64,
    /// Total frees to this CPU.
    free_count: u64,
    /// Refill operations.
    refills: u64,
    /// Drain operations.
    drains: u64,
}

impl PerCpuPageList {
    /// Create a new list for a CPU.
    pub const fn new(cpu_id: u32) -> Self {
        Self {
            cpu_id,
            pages: [0u64; DEFAULT_CAPACITY],
            count: 0,
            high: DEFAULT_CAPACITY,
            low: 0,
            alloc_count: 0,
            free_count: 0,
            refills: 0,
            drains: 0,
        }
    }

    /// Return the CPU ID.
    pub const fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Return the number of pages.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Check whether the list is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Check whether the list is full.
    pub const fn is_full(&self) -> bool {
        self.count >= self.high
    }

    /// Return the allocation count.
    pub const fn alloc_count(&self) -> u64 {
        self.alloc_count
    }

    /// Return the free count.
    pub const fn free_count(&self) -> u64 {
        self.free_count
    }

    /// Allocate a page from this list.
    pub fn alloc(&mut self) -> Result<u64> {
        if self.count == 0 {
            return Err(Error::OutOfMemory);
        }
        self.count -= 1;
        let pfn = self.pages[self.count];
        self.pages[self.count] = 0;
        self.alloc_count += 1;
        Ok(pfn)
    }

    /// Free a page to this list.
    pub fn free(&mut self, pfn: u64) -> Result<()> {
        if self.count >= DEFAULT_CAPACITY {
            return Err(Error::OutOfMemory);
        }
        self.pages[self.count] = pfn;
        self.count += 1;
        self.free_count += 1;
        Ok(())
    }

    /// Bulk add pages (refill from buddy).
    pub fn refill(&mut self, pfns: &[u64]) -> usize {
        let mut added = 0;
        for pfn in pfns {
            if self.count >= DEFAULT_CAPACITY {
                break;
            }
            self.pages[self.count] = *pfn;
            self.count += 1;
            added += 1;
        }
        if added > 0 {
            self.refills += 1;
        }
        added
    }

    /// Bulk remove pages (drain to buddy).
    pub fn drain(&mut self, buffer: &mut [u64]) -> usize {
        let n = buffer.len().min(self.count).min(BATCH_SIZE);
        for idx in 0..n {
            self.count -= 1;
            buffer[idx] = self.pages[self.count];
            self.pages[self.count] = 0;
        }
        if n > 0 {
            self.drains += 1;
        }
        n
    }

    /// Set watermarks.
    pub fn set_watermarks(&mut self, low: usize, high: usize) {
        self.low = low;
        self.high = high.min(DEFAULT_CAPACITY);
    }

    /// Check if refill is needed.
    pub const fn needs_refill(&self) -> bool {
        self.count <= self.low
    }

    /// Check if drain is needed.
    pub const fn needs_drain(&self) -> bool {
        self.count >= self.high
    }
}

impl Default for PerCpuPageList {
    fn default() -> Self {
        Self::new(0)
    }
}

// -------------------------------------------------------------------
// PerCpuPageStats
// -------------------------------------------------------------------

/// Global per-CPU page statistics.
#[derive(Debug, Clone, Copy)]
pub struct PerCpuPageStats {
    /// Total allocations.
    pub total_allocs: u64,
    /// Total frees.
    pub total_frees: u64,
    /// Total refills.
    pub total_refills: u64,
    /// Total drains.
    pub total_drains: u64,
    /// Total pages cached across all CPUs.
    pub total_cached: u64,
}

impl PerCpuPageStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            total_allocs: 0,
            total_frees: 0,
            total_refills: 0,
            total_drains: 0,
            total_cached: 0,
        }
    }
}

impl Default for PerCpuPageStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// PerCpuPageAllocator
// -------------------------------------------------------------------

/// Manages per-CPU page lists.
pub struct PerCpuPageAllocator {
    /// Per-CPU lists.
    lists: [PerCpuPageList; MAX_CPUS],
    /// Number of active CPUs.
    cpu_count: usize,
    /// Statistics.
    stats: PerCpuPageStats,
}

impl PerCpuPageAllocator {
    /// Create a new allocator.
    pub const fn new() -> Self {
        Self {
            lists: [const {
                PerCpuPageList {
                    cpu_id: 0,
                    pages: [0u64; DEFAULT_CAPACITY],
                    count: 0,
                    high: DEFAULT_CAPACITY,
                    low: 0,
                    alloc_count: 0,
                    free_count: 0,
                    refills: 0,
                    drains: 0,
                }
            }; MAX_CPUS],
            cpu_count: 0,
            stats: PerCpuPageStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &PerCpuPageStats {
        &self.stats
    }

    /// Return the number of active CPUs.
    pub const fn cpu_count(&self) -> usize {
        self.cpu_count
    }

    /// Initialize CPUs.
    pub fn init_cpus(&mut self, count: usize) -> Result<()> {
        if count > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        for idx in 0..count {
            self.lists[idx] = PerCpuPageList::new(idx as u32);
        }
        self.cpu_count = count;
        Ok(())
    }

    /// Allocate a page on a given CPU.
    pub fn alloc(&mut self, cpu: usize) -> Result<u64> {
        if cpu >= self.cpu_count {
            return Err(Error::InvalidArgument);
        }
        let pfn = self.lists[cpu].alloc()?;
        self.stats.total_allocs += 1;
        Ok(pfn)
    }

    /// Free a page on a given CPU.
    pub fn free(&mut self, cpu: usize, pfn: u64) -> Result<()> {
        if cpu >= self.cpu_count {
            return Err(Error::InvalidArgument);
        }
        self.lists[cpu].free(pfn)?;
        self.stats.total_frees += 1;
        Ok(())
    }

    /// Get a per-CPU list.
    pub fn get_list(&self, cpu: usize) -> Option<&PerCpuPageList> {
        if cpu < self.cpu_count {
            Some(&self.lists[cpu])
        } else {
            None
        }
    }

    /// Total cached pages across all CPUs.
    pub fn total_cached(&self) -> u64 {
        let mut total: u64 = 0;
        for idx in 0..self.cpu_count {
            total += self.lists[idx].count() as u64;
        }
        total
    }

    /// Total cached memory in bytes.
    pub fn total_cached_bytes(&self) -> u64 {
        self.total_cached() * PAGE_SIZE
    }
}

impl Default for PerCpuPageAllocator {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the maximum CPUs.
pub const fn max_cpus() -> usize {
    MAX_CPUS
}

/// Return the batch size.
pub const fn batch_size() -> usize {
    BATCH_SIZE
}

/// Return the default capacity.
pub const fn default_capacity() -> usize {
    DEFAULT_CAPACITY
}
