// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-CPU page allocation caches.
//!
//! Implements per-CPU page caches (PCP lists) that reduce contention
//! on the global buddy allocator. Each CPU maintains a small cache of
//! free pages, grouped by migration type. Allocations are served from
//! the local CPU's cache; when empty, it is refilled from the buddy
//! allocator in batches.
//!
//! - [`MigrateType`] — page mobility classification
//! - [`PcpList`] — per-CPU page cache for one migration type
//! - [`PcpSet`] — all PCP lists for one CPU
//! - [`PcpAllocator`] — the per-CPU allocator
//! - [`PcpStats`] — allocation statistics
//!
//! Reference: `.kernelORG/` — `mm/page_alloc.c` (per_cpu_pages),
//!   `include/linux/mmzone.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of CPUs.
const MAX_CPUS: usize = 32;

/// Number of migration types.
const NR_MIGRATE_TYPES: usize = 4;

/// Default PCP high watermark (max pages in cache).
const DEFAULT_PCP_HIGH: usize = 186;

/// Default PCP batch size (refill/drain batch).
const DEFAULT_PCP_BATCH: usize = 31;

/// Maximum pages per PCP list.
const MAX_PCP_PAGES: usize = 256;

// -------------------------------------------------------------------
// MigrateType
// -------------------------------------------------------------------

/// Page mobility classification for anti-fragmentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MigrateType {
    /// Unmovable pages (kernel allocations).
    #[default]
    Unmovable = 0,
    /// Movable pages (user-space, can be migrated).
    Movable = 1,
    /// Reclaimable pages (caches, can be freed).
    Reclaimable = 2,
    /// Reserved pages (CMA, special).
    Reserve = 3,
}

impl MigrateType {
    /// Returns the index for this type.
    pub fn as_index(self) -> usize {
        self as usize
    }

    /// Creates from index.
    pub fn from_index(idx: usize) -> Result<Self> {
        match idx {
            0 => Ok(MigrateType::Unmovable),
            1 => Ok(MigrateType::Movable),
            2 => Ok(MigrateType::Reclaimable),
            3 => Ok(MigrateType::Reserve),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// -------------------------------------------------------------------
// PcpList
// -------------------------------------------------------------------

/// Per-CPU page cache for a single migration type.
///
/// Maintains a stack of free page frame numbers for fast alloc/free.
pub struct PcpList {
    /// Free page frame numbers.
    pages: [u64; MAX_PCP_PAGES],
    /// Number of pages currently cached.
    count: usize,
    /// High watermark (trigger drain above this).
    high: usize,
    /// Batch size for refill/drain.
    batch: usize,
    /// Migration type.
    migrate_type: MigrateType,
}

impl PcpList {
    /// Creates a new PCP list.
    pub fn new(migrate_type: MigrateType) -> Self {
        Self {
            pages: [0u64; MAX_PCP_PAGES],
            count: 0,
            high: DEFAULT_PCP_HIGH,
            batch: DEFAULT_PCP_BATCH,
            migrate_type,
        }
    }

    /// Removes a page from the cache (alloc).
    pub fn rmqueue(&mut self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        Some(self.pages[self.count])
    }

    /// Adds a page to the cache (free).
    pub fn add(&mut self, pfn: u64) -> bool {
        if self.count >= MAX_PCP_PAGES {
            return false;
        }
        self.pages[self.count] = pfn;
        self.count += 1;
        true
    }

    /// Returns the number of cached pages.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns true if above the high watermark.
    pub fn is_over_high(&self) -> bool {
        self.count > self.high
    }

    /// Returns the high watermark.
    pub fn high(&self) -> usize {
        self.high
    }

    /// Returns the batch size.
    pub fn batch(&self) -> usize {
        self.batch
    }

    /// Sets the high watermark.
    pub fn set_high(&mut self, high: usize) {
        self.high = high.min(MAX_PCP_PAGES);
    }

    /// Sets the batch size.
    pub fn set_batch(&mut self, batch: usize) {
        self.batch = batch.min(MAX_PCP_PAGES / 2);
    }

    /// Returns the migration type.
    pub fn migrate_type(&self) -> MigrateType {
        self.migrate_type
    }

    /// Drains `n` pages from the cache, returning the count drained.
    pub fn drain(&mut self, n: usize) -> usize {
        let to_drain = n.min(self.count);
        self.count -= to_drain;
        to_drain
    }

    /// Refills the cache with pages from a source.
    pub fn refill(&mut self, pages: &[u64]) -> usize {
        let mut added = 0;
        for &pfn in pages {
            if self.count >= MAX_PCP_PAGES {
                break;
            }
            self.pages[self.count] = pfn;
            self.count += 1;
            added += 1;
        }
        added
    }
}

// -------------------------------------------------------------------
// PcpSet
// -------------------------------------------------------------------

/// All PCP lists for a single CPU.
pub struct PcpSet {
    /// Per-migration-type lists.
    lists: [PcpList; NR_MIGRATE_TYPES],
    /// CPU ID.
    cpu_id: u32,
    /// Whether this CPU is online.
    online: bool,
}

impl PcpSet {
    /// Creates a new PCP set for the given CPU.
    pub fn new(cpu_id: u32) -> Self {
        Self {
            lists: [
                PcpList::new(MigrateType::Unmovable),
                PcpList::new(MigrateType::Movable),
                PcpList::new(MigrateType::Reclaimable),
                PcpList::new(MigrateType::Reserve),
            ],
            cpu_id,
            online: true,
        }
    }

    /// Returns a reference to the list for a migration type.
    pub fn list(&self, mt: MigrateType) -> &PcpList {
        &self.lists[mt.as_index()]
    }

    /// Returns a mutable reference to the list for a migration type.
    pub fn list_mut(&mut self, mt: MigrateType) -> &mut PcpList {
        &mut self.lists[mt.as_index()]
    }

    /// Returns the total number of pages across all lists.
    pub fn total_count(&self) -> usize {
        self.lists.iter().map(|l| l.count()).sum()
    }

    /// Returns the CPU ID.
    pub fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Returns whether this CPU is online.
    pub fn is_online(&self) -> bool {
        self.online
    }

    /// Drains all pages from all lists (CPU offline).
    pub fn drain_all(&mut self) -> usize {
        let mut drained = 0;
        for list in &mut self.lists {
            drained += list.drain(list.count());
        }
        self.online = false;
        drained
    }
}

// -------------------------------------------------------------------
// PcpStats
// -------------------------------------------------------------------

/// Per-CPU allocator statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct PcpStats {
    /// Total allocations from PCP caches.
    pub pcp_allocs: u64,
    /// Total frees to PCP caches.
    pub pcp_frees: u64,
    /// Times PCP was empty and needed buddy refill.
    pub buddy_refills: u64,
    /// Times PCP was full and needed drain to buddy.
    pub buddy_drains: u64,
    /// Total pages drained on CPU offline.
    pub offline_drains: u64,
}

impl PcpStats {
    /// Resets all statistics.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// PcpAllocator
// -------------------------------------------------------------------

/// Per-CPU page allocator.
///
/// Each CPU has a [`PcpSet`] containing caches for each migration type.
/// Allocations go to the local CPU's cache; the buddy allocator is
/// accessed only for refill/drain in batches.
pub struct PcpAllocator {
    /// Per-CPU sets.
    cpus: [PcpSet; MAX_CPUS],
    /// Number of CPUs.
    nr_cpus: usize,
    /// Global statistics.
    stats: PcpStats,
    /// Next PFN to use for buddy refill simulation.
    next_buddy_pfn: u64,
}

impl PcpAllocator {
    /// Creates a new per-CPU allocator.
    pub fn new(nr_cpus: usize) -> Self {
        let nr = nr_cpus.min(MAX_CPUS);
        let mut cpus = [
            PcpSet::new(0),
            PcpSet::new(1),
            PcpSet::new(2),
            PcpSet::new(3),
            PcpSet::new(4),
            PcpSet::new(5),
            PcpSet::new(6),
            PcpSet::new(7),
            PcpSet::new(8),
            PcpSet::new(9),
            PcpSet::new(10),
            PcpSet::new(11),
            PcpSet::new(12),
            PcpSet::new(13),
            PcpSet::new(14),
            PcpSet::new(15),
            PcpSet::new(16),
            PcpSet::new(17),
            PcpSet::new(18),
            PcpSet::new(19),
            PcpSet::new(20),
            PcpSet::new(21),
            PcpSet::new(22),
            PcpSet::new(23),
            PcpSet::new(24),
            PcpSet::new(25),
            PcpSet::new(26),
            PcpSet::new(27),
            PcpSet::new(28),
            PcpSet::new(29),
            PcpSet::new(30),
            PcpSet::new(31),
        ];
        // Mark CPUs beyond nr as offline.
        for cpu_set in cpus.iter_mut().skip(nr) {
            cpu_set.online = false;
        }
        Self {
            cpus,
            nr_cpus: nr,
            stats: PcpStats::default(),
            next_buddy_pfn: 0x10_0000, // Start at 1 MiB.
        }
    }

    /// Allocates a page from the PCP cache of the given CPU.
    pub fn rmqueue_pcplist(&mut self, cpu: u32, migrate_type: MigrateType) -> Result<u64> {
        let cpu_idx = cpu as usize;
        if cpu_idx >= self.nr_cpus || !self.cpus[cpu_idx].online {
            return Err(Error::InvalidArgument);
        }

        let list = self.cpus[cpu_idx].list_mut(migrate_type);

        // Try to allocate from cache.
        if let Some(pfn) = list.rmqueue() {
            self.stats.pcp_allocs += 1;
            return Ok(pfn);
        }

        // Cache empty: refill from buddy.
        self.pcp_refill(cpu_idx, migrate_type)?;

        let list = self.cpus[cpu_idx].list_mut(migrate_type);
        list.rmqueue().ok_or(Error::OutOfMemory).map(|pfn| {
            self.stats.pcp_allocs += 1;
            pfn
        })
    }

    /// Frees a page to the PCP cache of the given CPU.
    pub fn free_pcppages(&mut self, cpu: u32, pfn: u64, migrate_type: MigrateType) -> Result<()> {
        let cpu_idx = cpu as usize;
        if cpu_idx >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }

        let list = self.cpus[cpu_idx].list_mut(migrate_type);

        if list.add(pfn) {
            self.stats.pcp_frees += 1;
        } else {
            // Cache full: drain batch to buddy, then add.
            self.free_pcppages_bulk(cpu_idx, migrate_type);
            let list = self.cpus[cpu_idx].list_mut(migrate_type);
            if !list.add(pfn) {
                return Err(Error::OutOfMemory);
            }
            self.stats.pcp_frees += 1;
        }

        Ok(())
    }

    /// Refills a PCP list from the buddy allocator.
    fn pcp_refill(&mut self, cpu_idx: usize, migrate_type: MigrateType) -> Result<()> {
        self.stats.buddy_refills += 1;
        let batch = self.cpus[cpu_idx].list(migrate_type).batch();

        // Simulate buddy allocation: generate sequential PFNs.
        let mut pfns = [0u64; 64];
        let count = batch.min(64);
        for pfn in pfns.iter_mut().take(count) {
            *pfn = self.next_buddy_pfn;
            self.next_buddy_pfn += 1;
        }

        let list = self.cpus[cpu_idx].list_mut(migrate_type);
        list.refill(&pfns[..count]);
        Ok(())
    }

    /// Drains a batch of pages from a PCP list to the buddy allocator.
    fn free_pcppages_bulk(&mut self, cpu_idx: usize, migrate_type: MigrateType) {
        self.stats.buddy_drains += 1;
        let batch = self.cpus[cpu_idx].list(migrate_type).batch();
        self.cpus[cpu_idx].list_mut(migrate_type).drain(batch);
    }

    /// Drains all PCP pages for a CPU going offline.
    pub fn drain_pages(&mut self, cpu: u32) -> Result<usize> {
        let cpu_idx = cpu as usize;
        if cpu_idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let drained = self.cpus[cpu_idx].drain_all();
        self.stats.offline_drains += drained as u64;
        Ok(drained)
    }

    /// Returns the PCP set for a CPU.
    pub fn cpu_set(&self, cpu: u32) -> Option<&PcpSet> {
        let idx = cpu as usize;
        if idx >= self.nr_cpus {
            return None;
        }
        Some(&self.cpus[idx])
    }

    /// Returns statistics.
    pub fn stats(&self) -> &PcpStats {
        &self.stats
    }

    /// Returns the number of CPUs.
    pub fn nr_cpus(&self) -> usize {
        self.nr_cpus
    }
}
