// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Free area management for the buddy allocator.
//!
//! Each allocation order has a [`FreeArea`] containing per-migrate-type
//! free lists. Pages are classified by their migrate type (Unmovable,
//! Movable, Reclaimable, etc.) so that movable and unmovable
//! allocations are kept separate, reducing fragmentation.
//!
//! - [`MigrateType`] — page migration classification
//! - [`FreeList`] — per-migrate-type list of free PFNs
//! - [`FreeArea`] — per-order container of free lists
//! - [`FreeAreaSet`] — all orders together (the buddy free-area array)
//! - [`FreeAreaStats`] — aggregate statistics
//!
//! Reference: `.kernelORG/` — `mm/page_alloc.c`, `include/linux/mmzone.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum allocation order (2^MAX_ORDER pages).
const MAX_ORDER: usize = 11;

/// Number of migrate types.
const NR_MIGRATE_TYPES: usize = 5;

/// Maximum free blocks per list.
const MAX_FREE_BLOCKS: usize = 128;

/// Standard page size (4 KiB).
const _PAGE_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// MigrateType
// -------------------------------------------------------------------

/// Page migration classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MigrateType {
    /// Pages that cannot be moved (kernel allocations).
    #[default]
    Unmovable = 0,
    /// Pages that can be moved (user pages).
    Movable = 1,
    /// Pages that can be reclaimed (page cache, slabs).
    Reclaimable = 2,
    /// Pages reserved for high-order allocations.
    HighAtomic = 3,
    /// CMA pages (Contiguous Memory Allocator).
    Cma = 4,
}

impl MigrateType {
    /// Returns the fallback order when this type is exhausted.
    pub fn fallback_order(self) -> &'static [MigrateType] {
        match self {
            MigrateType::Unmovable => &[MigrateType::Reclaimable, MigrateType::Movable],
            MigrateType::Movable => &[MigrateType::Reclaimable, MigrateType::Unmovable],
            MigrateType::Reclaimable => &[MigrateType::Unmovable, MigrateType::Movable],
            MigrateType::HighAtomic => &[
                MigrateType::Unmovable,
                MigrateType::Reclaimable,
                MigrateType::Movable,
            ],
            MigrateType::Cma => &[MigrateType::Movable, MigrateType::Unmovable],
        }
    }
}

// -------------------------------------------------------------------
// FreeList
// -------------------------------------------------------------------

/// Per-migrate-type list of free page-block PFNs at a given order.
#[derive(Debug)]
pub struct FreeList {
    /// Free block PFNs.
    blocks: [u64; MAX_FREE_BLOCKS],
    /// Number of free blocks.
    nr_free: usize,
    /// Migrate type.
    migrate_type: MigrateType,
}

impl Default for FreeList {
    fn default() -> Self {
        Self {
            blocks: [0u64; MAX_FREE_BLOCKS],
            nr_free: 0,
            migrate_type: MigrateType::Unmovable,
        }
    }
}

impl FreeList {
    /// Creates a free list for the given migrate type.
    fn new(migrate_type: MigrateType) -> Self {
        Self {
            migrate_type,
            ..Self::default()
        }
    }

    /// Adds a free block PFN to the list.
    pub fn add(&mut self, pfn: u64) -> Result<()> {
        if self.nr_free >= MAX_FREE_BLOCKS {
            return Err(Error::OutOfMemory);
        }
        self.blocks[self.nr_free] = pfn;
        self.nr_free += 1;
        Ok(())
    }

    /// Removes and returns a free block PFN.
    pub fn remove(&mut self) -> Option<u64> {
        if self.nr_free == 0 {
            return None;
        }
        self.nr_free -= 1;
        Some(self.blocks[self.nr_free])
    }

    /// Removes a specific PFN if present.
    pub fn remove_specific(&mut self, pfn: u64) -> bool {
        for i in 0..self.nr_free {
            if self.blocks[i] == pfn {
                self.nr_free -= 1;
                self.blocks[i] = self.blocks[self.nr_free];
                return true;
            }
        }
        false
    }

    /// Returns the number of free blocks.
    pub fn count(&self) -> usize {
        self.nr_free
    }

    /// Returns `true` if empty.
    pub fn is_empty(&self) -> bool {
        self.nr_free == 0
    }

    /// Returns the migrate type.
    pub fn migrate_type(&self) -> MigrateType {
        self.migrate_type
    }
}

// -------------------------------------------------------------------
// FreeArea
// -------------------------------------------------------------------

/// Per-order container of free lists (one per migrate type).
pub struct FreeArea {
    /// Per-migrate-type free lists.
    lists: [FreeList; NR_MIGRATE_TYPES],
    /// Total number of free blocks across all migrate types.
    nr_free: usize,
    /// Allocation order.
    order: usize,
}

impl Default for FreeArea {
    fn default() -> Self {
        Self {
            lists: [const {
                FreeList {
                    blocks: [0u64; MAX_FREE_BLOCKS],
                    nr_free: 0,
                    migrate_type: MigrateType::Unmovable,
                }
            }; NR_MIGRATE_TYPES],
            nr_free: 0,
            order: 0,
        }
    }
}

impl FreeArea {
    /// Creates a free area for the given order.
    pub fn new(order: usize) -> Self {
        let mut area = Self {
            order,
            ..Self::default()
        };
        area.lists[0] = FreeList::new(MigrateType::Unmovable);
        area.lists[1] = FreeList::new(MigrateType::Movable);
        area.lists[2] = FreeList::new(MigrateType::Reclaimable);
        area.lists[3] = FreeList::new(MigrateType::HighAtomic);
        area.lists[4] = FreeList::new(MigrateType::Cma);
        area
    }

    /// Adds a block to the specified migrate type's list.
    pub fn add_to_free_area(&mut self, pfn: u64, migrate: MigrateType) -> Result<()> {
        let idx = migrate as usize;
        if idx >= NR_MIGRATE_TYPES {
            return Err(Error::InvalidArgument);
        }
        self.lists[idx].add(pfn)?;
        self.nr_free += 1;
        Ok(())
    }

    /// Removes a block from the specified migrate type's list.
    pub fn del_from_free_area(&mut self, migrate: MigrateType) -> Option<u64> {
        let idx = migrate as usize;
        if idx >= NR_MIGRATE_TYPES {
            return None;
        }
        let pfn = self.lists[idx].remove();
        if pfn.is_some() {
            self.nr_free = self.nr_free.saturating_sub(1);
        }
        pfn
    }

    /// Removes a specific PFN from the given migrate type's list.
    pub fn del_specific(&mut self, pfn: u64, migrate: MigrateType) -> bool {
        let idx = migrate as usize;
        if idx >= NR_MIGRATE_TYPES {
            return false;
        }
        if self.lists[idx].remove_specific(pfn) {
            self.nr_free = self.nr_free.saturating_sub(1);
            true
        } else {
            false
        }
    }

    /// Finds a suitable fallback migrate type when the requested
    /// type is empty.
    pub fn find_suitable_fallback(&mut self, requested: MigrateType) -> Option<(u64, MigrateType)> {
        // Try requested type first.
        if let Some(pfn) = self.del_from_free_area(requested) {
            return Some((pfn, requested));
        }
        // Try fallback order.
        for &fallback in requested.fallback_order() {
            if let Some(pfn) = self.del_from_free_area(fallback) {
                return Some((pfn, fallback));
            }
        }
        None
    }

    /// Moves free pages from one migrate type to another.
    pub fn move_freepages_block(
        &mut self,
        from: MigrateType,
        to: MigrateType,
        max_count: usize,
    ) -> usize {
        let from_idx = from as usize;
        let to_idx = to as usize;
        if from_idx >= NR_MIGRATE_TYPES || to_idx >= NR_MIGRATE_TYPES || from_idx == to_idx {
            return 0;
        }

        let mut moved = 0;
        while moved < max_count {
            // We need to index two elements simultaneously, so
            // use raw index access for the source list.
            let pfn = self.lists[from_idx].remove();
            match pfn {
                Some(p) => {
                    if self.lists[to_idx].add(p).is_err() {
                        // Target full — put it back.
                        let _ = self.lists[from_idx].add(p);
                        break;
                    }
                    moved += 1;
                }
                None => break,
            }
        }
        moved
    }

    /// Returns total free blocks in this area.
    pub fn total_free(&self) -> usize {
        self.nr_free
    }

    /// Returns the allocation order.
    pub fn order(&self) -> usize {
        self.order
    }

    /// Returns free count for a specific migrate type.
    pub fn free_count(&self, migrate: MigrateType) -> usize {
        let idx = migrate as usize;
        if idx < NR_MIGRATE_TYPES {
            self.lists[idx].count()
        } else {
            0
        }
    }
}

// -------------------------------------------------------------------
// FreeAreaStats
// -------------------------------------------------------------------

/// Aggregate free-area statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct FreeAreaStats {
    /// Total free blocks per order.
    pub per_order: [usize; MAX_ORDER],
    /// Total free blocks per migrate type.
    pub per_migrate: [usize; NR_MIGRATE_TYPES],
    /// Grand total free blocks.
    pub total_free: usize,
}

// -------------------------------------------------------------------
// FreeAreaSet
// -------------------------------------------------------------------

/// Complete set of free areas (one per order) — the buddy
/// allocator's main data structure.
pub struct FreeAreaSet {
    /// Per-order free areas.
    areas: [FreeArea; MAX_ORDER],
}

impl Default for FreeAreaSet {
    fn default() -> Self {
        Self {
            areas: [const {
                FreeArea {
                    lists: [const {
                        FreeList {
                            blocks: [0u64; MAX_FREE_BLOCKS],
                            nr_free: 0,
                            migrate_type: MigrateType::Unmovable,
                        }
                    }; NR_MIGRATE_TYPES],
                    nr_free: 0,
                    order: 0,
                }
            }; MAX_ORDER],
        }
    }
}

impl FreeAreaSet {
    /// Creates a new free-area set with properly initialised orders.
    pub fn new() -> Self {
        let mut set = Self::default();
        for i in 0..MAX_ORDER {
            set.areas[i] = FreeArea::new(i);
        }
        set
    }

    /// Returns a reference to the free area at the given order.
    pub fn area(&self, order: usize) -> Option<&FreeArea> {
        if order < MAX_ORDER {
            Some(&self.areas[order])
        } else {
            None
        }
    }

    /// Returns a mutable reference to the free area at the given
    /// order.
    pub fn area_mut(&mut self, order: usize) -> Option<&mut FreeArea> {
        if order < MAX_ORDER {
            Some(&mut self.areas[order])
        } else {
            None
        }
    }

    /// Collects statistics across all orders and migrate types.
    pub fn stats(&self) -> FreeAreaStats {
        let mut s = FreeAreaStats::default();
        for i in 0..MAX_ORDER {
            let total = self.areas[i].total_free();
            s.per_order[i] = total;
            s.total_free += total;
            for mt in 0..NR_MIGRATE_TYPES {
                s.per_migrate[mt] += self.areas[i].lists[mt].count();
            }
        }
        s
    }

    /// Returns total free blocks across all orders.
    pub fn total_free(&self) -> usize {
        self.areas.iter().map(|a| a.total_free()).sum()
    }
}
