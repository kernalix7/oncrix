// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! I/O Virtual Address (IOVA) domain management.
//!
//! Provides an IOVA allocator for IOMMU address space management.
//! Supports fast allocation and free using a sorted array (modeling
//! a red-black tree), per-domain address space, IOVA caching via
//! a magazine layer for hot-path reuse, and a flush queue for
//! deferred TLB invalidation.
//!
//! # Key Types
//!
//! - [`IovaRange`] — a single IOVA range (start, size)
//! - [`IovaDomain`] — per-domain IOVA address space
//! - [`IovaMagazine`] — per-CPU IOVA cache (magazine layer)
//! - [`IovaFlushEntry`] — entry in the deferred flush queue
//! - [`IovaFlushQueue`] — deferred invalidation queue
//! - [`IovaDomainManager`] — system-wide domain registry
//! - [`IovaStats`] — allocation statistics
//!
//! Reference: Linux `drivers/iommu/iova.c`,
//! `include/linux/iova.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Default IOVA page size (4 KiB).
const IOVA_PAGE_SIZE: u64 = 4096;

/// Maximum IOVA ranges per domain.
const MAX_RANGES: usize = 512;

/// Maximum IOVA domains in the system.
const MAX_DOMAINS: usize = 16;

/// Magazine capacity (cached IOVAs per CPU).
const MAGAZINE_SIZE: usize = 32;

/// Maximum CPUs for per-CPU magazines.
const MAX_CPUS: usize = 8;

/// Flush queue capacity.
const FLUSH_QUEUE_SIZE: usize = 128;

/// Default IOVA address space start.
const DEFAULT_START: u64 = 0x1000;

/// Default IOVA address space end.
const DEFAULT_END: u64 = 0xFFFF_FFFF_FFFF;

/// Maximum size of a single IOVA allocation (256 MiB in pages).
const MAX_ALLOC_PAGES: u64 = 65536;

// -------------------------------------------------------------------
// IovaRange
// -------------------------------------------------------------------

/// A single IOVA range representing an allocated or free region.
#[derive(Debug, Clone, Copy, Default)]
pub struct IovaRange {
    /// Start address (page-frame number in IOVA space).
    pub start_pfn: u64,
    /// Size in pages.
    pub size_pages: u64,
    /// Whether this range is allocated (true) or free (false).
    pub allocated: bool,
    /// Domain ID this range belongs to.
    pub domain_id: u32,
    /// Generation counter for ABA detection.
    pub generation: u32,
}

impl IovaRange {
    /// Returns the end PFN (exclusive).
    pub fn end_pfn(&self) -> u64 {
        self.start_pfn + self.size_pages
    }

    /// Returns the size in bytes.
    pub fn size_bytes(&self) -> u64 {
        self.size_pages * IOVA_PAGE_SIZE
    }

    /// Returns the start address in bytes.
    pub fn start_addr(&self) -> u64 {
        self.start_pfn * IOVA_PAGE_SIZE
    }

    /// Returns the end address in bytes (exclusive).
    pub fn end_addr(&self) -> u64 {
        self.end_pfn() * IOVA_PAGE_SIZE
    }
}

// -------------------------------------------------------------------
// IovaDomain
// -------------------------------------------------------------------

/// Per-domain IOVA address space.
///
/// Maintains a sorted array of allocated ranges (modeling a
/// red-black tree). Allocation uses a top-down search from the
/// highest available address.
pub struct IovaDomain {
    /// Domain identifier.
    domain_id: u32,
    /// Allocated ranges, sorted by start_pfn.
    ranges: [IovaRange; MAX_RANGES],
    /// Number of allocated ranges.
    nr_ranges: usize,
    /// Start of the address space (PFN).
    start_pfn: u64,
    /// End of the address space (PFN, exclusive).
    end_pfn: u64,
    /// Hint: highest address where last alloc succeeded.
    alloc_hint: u64,
    /// Generation counter.
    generation: u32,
    /// Whether this domain is active.
    active: bool,
    /// Total allocations.
    alloc_count: u64,
    /// Total frees.
    free_count: u64,
    /// Failed allocations.
    failed_allocs: u64,
}

impl IovaDomain {
    /// Creates a new domain with default address bounds.
    pub fn new(domain_id: u32) -> Self {
        let start = DEFAULT_START / IOVA_PAGE_SIZE;
        let end = DEFAULT_END / IOVA_PAGE_SIZE;
        Self {
            domain_id,
            ranges: [IovaRange::default(); MAX_RANGES],
            nr_ranges: 0,
            start_pfn: start,
            end_pfn: end,
            alloc_hint: end,
            generation: 0,
            active: true,
            alloc_count: 0,
            free_count: 0,
            failed_allocs: 0,
        }
    }

    /// Creates a domain with custom address bounds.
    pub fn with_bounds(domain_id: u32, start_pfn: u64, end_pfn: u64) -> Self {
        Self {
            domain_id,
            ranges: [IovaRange::default(); MAX_RANGES],
            nr_ranges: 0,
            start_pfn,
            end_pfn,
            alloc_hint: end_pfn,
            generation: 0,
            active: true,
            alloc_count: 0,
            free_count: 0,
            failed_allocs: 0,
        }
    }

    /// Allocates `size_pages` of contiguous IOVA space.
    ///
    /// Uses a top-down search starting from the allocation hint.
    /// Returns the start PFN of the allocated range.
    pub fn alloc(&mut self, size_pages: u64) -> Result<u64> {
        if !self.active || size_pages == 0 || size_pages > MAX_ALLOC_PAGES {
            return Err(Error::InvalidArgument);
        }
        if self.nr_ranges >= MAX_RANGES {
            self.failed_allocs += 1;
            return Err(Error::OutOfMemory);
        }

        // Find a gap large enough, searching top-down.
        let candidate = self.find_gap_topdown(size_pages);
        let start = candidate.ok_or_else(|| {
            self.failed_allocs += 1;
            Error::OutOfMemory
        })?;

        // Insert the range (maintaining sorted order).
        self.insert_range(IovaRange {
            start_pfn: start,
            size_pages,
            allocated: true,
            domain_id: self.domain_id,
            generation: self.generation,
        });

        self.alloc_hint = start;
        self.alloc_count += 1;
        self.generation += 1;
        Ok(start)
    }

    /// Frees an IOVA range starting at `start_pfn`.
    pub fn free(&mut self, start_pfn: u64) -> Result<IovaRange> {
        let pos = self.find_range(start_pfn).ok_or(Error::NotFound)?;
        let range = self.ranges[pos];

        // Remove by shifting.
        for i in pos..self.nr_ranges - 1 {
            self.ranges[i] = self.ranges[i + 1];
        }
        self.nr_ranges -= 1;

        // Update hint to allow reuse of freed space.
        if start_pfn + range.size_pages > self.alloc_hint {
            self.alloc_hint = start_pfn + range.size_pages;
        }

        self.free_count += 1;
        Ok(range)
    }

    /// Looks up an IOVA range by start PFN.
    pub fn lookup(&self, start_pfn: u64) -> Option<&IovaRange> {
        let pos = self.find_range(start_pfn)?;
        Some(&self.ranges[pos])
    }

    /// Returns the domain ID.
    pub fn domain_id(&self) -> u32 {
        self.domain_id
    }

    /// Returns the number of allocated ranges.
    pub fn nr_ranges(&self) -> usize {
        self.nr_ranges
    }

    /// Returns `true` if the domain is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Deactivates the domain.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Returns total allocated IOVA pages.
    pub fn allocated_pages(&self) -> u64 {
        let mut total = 0u64;
        for i in 0..self.nr_ranges {
            total += self.ranges[i].size_pages;
        }
        total
    }

    /// Returns the free IOVA pages (approximate).
    pub fn free_pages(&self) -> u64 {
        let total = self.end_pfn.saturating_sub(self.start_pfn);
        total.saturating_sub(self.allocated_pages())
    }

    // -- internal --

    /// Finds a gap of `size_pages` searching top-down.
    fn find_gap_topdown(&self, size_pages: u64) -> Option<u64> {
        // Start from the hint (or domain end).
        let mut ceiling = self.alloc_hint.min(self.end_pfn);

        // Walk allocated ranges in reverse order.
        let mut idx = self.nr_ranges;
        while idx > 0 {
            idx -= 1;
            let range = &self.ranges[idx];
            if range.end_pfn() > ceiling {
                continue;
            }
            // Check gap above this range.
            let gap_start = range.end_pfn();
            if ceiling >= gap_start + size_pages {
                let candidate = ceiling - size_pages;
                if candidate >= gap_start && candidate >= self.start_pfn {
                    return Some(candidate);
                }
            }
            ceiling = range.start_pfn;
        }

        // Check gap below the lowest range.
        if ceiling >= self.start_pfn + size_pages {
            let candidate = ceiling - size_pages;
            if candidate >= self.start_pfn {
                return Some(candidate);
            }
        }

        // Retry without hint (from domain end).
        if self.alloc_hint < self.end_pfn {
            let mut ceil2 = self.end_pfn;
            let mut i = self.nr_ranges;
            while i > 0 {
                i -= 1;
                let r = &self.ranges[i];
                let gap_start = r.end_pfn();
                if ceil2 >= gap_start + size_pages {
                    let c = ceil2 - size_pages;
                    if c >= gap_start && c >= self.start_pfn {
                        return Some(c);
                    }
                }
                ceil2 = r.start_pfn;
            }
            if ceil2 >= self.start_pfn + size_pages {
                let c = ceil2 - size_pages;
                if c >= self.start_pfn {
                    return Some(c);
                }
            }
        }

        None
    }

    /// Inserts a range maintaining sorted order by start_pfn.
    fn insert_range(&mut self, range: IovaRange) {
        // Find insertion point.
        let mut pos = self.nr_ranges;
        for i in 0..self.nr_ranges {
            if self.ranges[i].start_pfn > range.start_pfn {
                pos = i;
                break;
            }
        }

        // Shift entries right.
        let mut i = self.nr_ranges;
        while i > pos {
            self.ranges[i] = self.ranges[i - 1];
            i -= 1;
        }
        self.ranges[pos] = range;
        self.nr_ranges += 1;
    }

    /// Finds a range by start PFN using binary search.
    fn find_range(&self, start_pfn: u64) -> Option<usize> {
        let mut lo = 0usize;
        let mut hi = self.nr_ranges;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.ranges[mid].start_pfn == start_pfn {
                return Some(mid);
            } else if self.ranges[mid].start_pfn < start_pfn {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        None
    }
}

// -------------------------------------------------------------------
// IovaMagazine
// -------------------------------------------------------------------

/// Per-CPU IOVA cache (magazine layer).
///
/// Caches recently freed IOVA ranges for fast reuse, avoiding the
/// cost of tree traversal on every allocation.
pub struct IovaMagazine {
    /// Cached IOVA start PFNs.
    entries: [u64; MAGAZINE_SIZE],
    /// Cached sizes (in pages).
    sizes: [u64; MAGAZINE_SIZE],
    /// Number of cached entries.
    count: usize,
    /// CPU this magazine belongs to.
    cpu_id: u32,
    /// Cache hits.
    hits: u64,
    /// Cache misses.
    misses: u64,
}

impl IovaMagazine {
    /// Creates an empty magazine for the given CPU.
    const fn new(cpu_id: u32) -> Self {
        Self {
            entries: [0u64; MAGAZINE_SIZE],
            sizes: [0u64; MAGAZINE_SIZE],
            count: 0,
            cpu_id,
            hits: 0,
            misses: 0,
        }
    }

    /// Attempts to get a cached IOVA of at least `size_pages`.
    pub fn get(&mut self, size_pages: u64) -> Option<(u64, u64)> {
        for i in 0..self.count {
            if self.sizes[i] >= size_pages {
                let pfn = self.entries[i];
                let sz = self.sizes[i];
                // Remove by swap with last.
                self.entries[i] = self.entries[self.count - 1];
                self.sizes[i] = self.sizes[self.count - 1];
                self.count -= 1;
                self.hits += 1;
                return Some((pfn, sz));
            }
        }
        self.misses += 1;
        None
    }

    /// Puts a freed IOVA into the magazine cache.
    pub fn put(&mut self, start_pfn: u64, size_pages: u64) -> bool {
        if self.count >= MAGAZINE_SIZE {
            return false;
        }
        self.entries[self.count] = start_pfn;
        self.sizes[self.count] = size_pages;
        self.count += 1;
        true
    }

    /// Returns the number of cached entries.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns the CPU ID.
    pub fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Returns cache hits.
    pub fn hits(&self) -> u64 {
        self.hits
    }

    /// Returns cache misses.
    pub fn misses(&self) -> u64 {
        self.misses
    }

    /// Drains the magazine, returning all entries.
    pub fn drain(&mut self) -> usize {
        let count = self.count;
        self.count = 0;
        count
    }
}

// -------------------------------------------------------------------
// IovaFlushEntry
// -------------------------------------------------------------------

/// Entry in the deferred IOVA invalidation queue.
#[derive(Debug, Clone, Copy, Default)]
pub struct IovaFlushEntry {
    /// IOVA start PFN.
    pub start_pfn: u64,
    /// Size in pages.
    pub size_pages: u64,
    /// Domain ID.
    pub domain_id: u32,
    /// Flush counter at time of queueing.
    pub counter: u64,
}

// -------------------------------------------------------------------
// IovaFlushQueue
// -------------------------------------------------------------------

/// Deferred IOVA invalidation queue.
///
/// Batches TLB invalidations to reduce IOMMU flush overhead.
/// When the queue is full or a timeout fires, all entries are
/// flushed in a single batch operation.
pub struct IovaFlushQueue {
    /// Queue entries.
    entries: [IovaFlushEntry; FLUSH_QUEUE_SIZE],
    /// Number of valid entries.
    count: usize,
    /// Monotonic flush counter.
    counter: u64,
    /// Total flushes performed.
    total_flushes: u64,
    /// Total entries flushed.
    total_entries_flushed: u64,
}

impl IovaFlushQueue {
    /// Creates an empty flush queue.
    pub const fn new() -> Self {
        Self {
            entries: [IovaFlushEntry {
                start_pfn: 0,
                size_pages: 0,
                domain_id: 0,
                counter: 0,
            }; FLUSH_QUEUE_SIZE],
            count: 0,
            counter: 0,
            total_flushes: 0,
            total_entries_flushed: 0,
        }
    }

    /// Queues an IOVA range for deferred invalidation.
    ///
    /// If the queue is full, triggers an immediate flush first.
    pub fn queue(&mut self, start_pfn: u64, size_pages: u64, domain_id: u32) -> Result<()> {
        if self.count >= FLUSH_QUEUE_SIZE {
            self.flush();
        }
        self.entries[self.count] = IovaFlushEntry {
            start_pfn,
            size_pages,
            domain_id,
            counter: self.counter,
        };
        self.count += 1;
        self.counter += 1;
        Ok(())
    }

    /// Flushes all queued entries. Returns the number flushed.
    pub fn flush(&mut self) -> usize {
        let flushed = self.count;
        self.total_entries_flushed += flushed as u64;
        if flushed > 0 {
            self.total_flushes += 1;
        }
        self.count = 0;
        flushed
    }

    /// Returns the number of pending entries.
    pub fn pending(&self) -> usize {
        self.count
    }

    /// Returns total flush operations.
    pub fn total_flushes(&self) -> u64 {
        self.total_flushes
    }

    /// Returns total entries flushed.
    pub fn total_entries_flushed(&self) -> u64 {
        self.total_entries_flushed
    }
}

impl Default for IovaFlushQueue {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// IovaStats
// -------------------------------------------------------------------

/// IOVA allocation statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct IovaStats {
    /// Total allocations.
    pub allocs: u64,
    /// Total frees.
    pub frees: u64,
    /// Failed allocations.
    pub failures: u64,
    /// Magazine cache hits.
    pub cache_hits: u64,
    /// Magazine cache misses.
    pub cache_misses: u64,
    /// Total flush operations.
    pub flushes: u64,
    /// Total allocated IOVA pages.
    pub allocated_pages: u64,
    /// Active domains.
    pub active_domains: usize,
}

// -------------------------------------------------------------------
// IovaDomainManager
// -------------------------------------------------------------------

/// System-wide IOVA domain registry.
///
/// Manages multiple IOVA domains, per-CPU magazine caches, and a
/// shared flush queue.
pub struct IovaDomainManager {
    /// Registered domains.
    domains: [Option<IovaDomain>; MAX_DOMAINS],
    /// Number of active domains.
    nr_domains: usize,
    /// Per-CPU IOVA magazines.
    magazines: [IovaMagazine; MAX_CPUS],
    /// Shared flush queue.
    flush_queue: IovaFlushQueue,
    /// Next domain ID.
    next_id: u32,
}

impl IovaDomainManager {
    /// Creates an empty manager.
    pub const fn new() -> Self {
        const NONE: Option<IovaDomain> = None;
        Self {
            domains: [NONE; MAX_DOMAINS],
            nr_domains: 0,
            magazines: [
                IovaMagazine::new(0),
                IovaMagazine::new(1),
                IovaMagazine::new(2),
                IovaMagazine::new(3),
                IovaMagazine::new(4),
                IovaMagazine::new(5),
                IovaMagazine::new(6),
                IovaMagazine::new(7),
            ],
            flush_queue: IovaFlushQueue::new(),
            next_id: 1,
        }
    }

    /// Creates and registers a new IOVA domain.
    pub fn create_domain(&mut self) -> Result<u32> {
        let slot = self.find_empty().ok_or(Error::OutOfMemory)?;
        let id = self.next_id;
        self.domains[slot] = Some(IovaDomain::new(id));
        self.nr_domains += 1;
        self.next_id += 1;
        Ok(id)
    }

    /// Creates a domain with custom address bounds.
    pub fn create_domain_with_bounds(&mut self, start_pfn: u64, end_pfn: u64) -> Result<u32> {
        let slot = self.find_empty().ok_or(Error::OutOfMemory)?;
        let id = self.next_id;
        self.domains[slot] = Some(IovaDomain::with_bounds(id, start_pfn, end_pfn));
        self.nr_domains += 1;
        self.next_id += 1;
        Ok(id)
    }

    /// Allocates IOVA from a domain, checking magazine cache first.
    pub fn alloc(&mut self, domain_id: u32, size_pages: u64, cpu: usize) -> Result<u64> {
        // Try magazine cache.
        if cpu < MAX_CPUS {
            if let Some((pfn, _sz)) = self.magazines[cpu].get(size_pages) {
                return Ok(pfn);
            }
        }

        // Fall back to domain allocator.
        let domain = self.find_domain_mut(domain_id)?;
        domain.alloc(size_pages)
    }

    /// Frees IOVA, placing in magazine cache or flush queue.
    pub fn free(&mut self, domain_id: u32, start_pfn: u64, cpu: usize) -> Result<()> {
        let domain = self.find_domain_mut(domain_id)?;
        let range = domain.free(start_pfn)?;

        // Try magazine cache.
        if cpu < MAX_CPUS {
            if self.magazines[cpu].put(range.start_pfn, range.size_pages) {
                return Ok(());
            }
        }

        // Queue for deferred flush.
        let _ = self
            .flush_queue
            .queue(range.start_pfn, range.size_pages, domain_id);
        Ok(())
    }

    /// Destroys a domain by ID.
    pub fn destroy_domain(&mut self, domain_id: u32) -> Result<()> {
        for i in 0..MAX_DOMAINS {
            let matches = self.domains[i]
                .as_ref()
                .map_or(false, |d| d.domain_id == domain_id);
            if matches {
                self.domains[i] = None;
                self.nr_domains -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Flushes the deferred invalidation queue.
    pub fn flush(&mut self) -> usize {
        self.flush_queue.flush()
    }

    /// Returns aggregate statistics.
    pub fn stats(&self) -> IovaStats {
        let mut s = IovaStats::default();
        for i in 0..MAX_DOMAINS {
            if let Some(d) = &self.domains[i] {
                s.allocs += d.alloc_count;
                s.frees += d.free_count;
                s.failures += d.failed_allocs;
                s.allocated_pages += d.allocated_pages();
                if d.active {
                    s.active_domains += 1;
                }
            }
        }
        for i in 0..MAX_CPUS {
            s.cache_hits += self.magazines[i].hits;
            s.cache_misses += self.magazines[i].misses;
        }
        s.flushes = self.flush_queue.total_flushes;
        s
    }

    /// Returns the number of active domains.
    pub fn nr_domains(&self) -> usize {
        self.nr_domains
    }

    /// Returns a reference to the flush queue.
    pub fn flush_queue(&self) -> &IovaFlushQueue {
        &self.flush_queue
    }

    // -- internal --

    /// Finds a domain by ID (mutable).
    fn find_domain_mut(&mut self, domain_id: u32) -> Result<&mut IovaDomain> {
        let pos = (0..MAX_DOMAINS)
            .find(|&i| {
                self.domains[i]
                    .as_ref()
                    .is_some_and(|d| d.domain_id == domain_id)
            })
            .ok_or(Error::NotFound)?;
        self.domains[pos].as_mut().ok_or(Error::NotFound)
    }

    /// Finds the first empty slot.
    fn find_empty(&self) -> Option<usize> {
        for i in 0..MAX_DOMAINS {
            if self.domains[i].is_none() {
                return Some(i);
            }
        }
        None
    }
}

impl Default for IovaDomainManager {
    fn default() -> Self {
        Self::new()
    }
}
