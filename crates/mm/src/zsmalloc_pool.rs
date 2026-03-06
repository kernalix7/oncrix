// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! zsmalloc pool management.
//!
//! Implements the zsmalloc allocator used by zram/zswap for compact
//! storage of compressed pages. Objects are packed into "zpages"
//! (pairs of physical pages) to minimize fragmentation and memory
//! overhead for variable-size compressed data.
//!
//! - [`SizeClass`] — size class for object grouping
//! - [`ZsPage`] — a zsmalloc page (pair of physical pages)
//! - [`ZsHandle`] — an opaque handle to an allocated object
//! - [`ZsPoolStats`] — pool statistics
//! - [`ZsPool`] — the zsmalloc memory pool
//!
//! Reference: Linux `mm/zsmalloc.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size.
const PAGE_SIZE: u64 = 4096;

/// Minimum object size.
const MIN_OBJ_SIZE: usize = 32;

/// Maximum object size (almost a full page).
const MAX_OBJ_SIZE: usize = 3840;

/// Number of size classes.
const NR_SIZE_CLASSES: usize = 32;

/// Maximum zpages per pool.
const MAX_ZPAGES: usize = 256;

/// Maximum objects per zpage.
const MAX_OBJS_PER_ZPAGE: usize = 128;

// -------------------------------------------------------------------
// SizeClass
// -------------------------------------------------------------------

/// A size class groups objects of similar sizes.
#[derive(Debug, Clone, Copy, Default)]
pub struct SizeClass {
    /// Size class index.
    pub index: usize,
    /// Object size for this class (bytes).
    pub size: usize,
    /// Maximum objects per zpage.
    pub objs_per_page: usize,
    /// Number of zpages allocated for this class.
    pub nr_zpages: usize,
    /// Total objects allocated.
    pub obj_count: u64,
}

impl SizeClass {
    /// Creates a new size class.
    pub fn new(index: usize, size: usize) -> Self {
        let usable = (PAGE_SIZE as usize) * 2;
        let objs_per_page = if size > 0 {
            (usable / size).min(MAX_OBJS_PER_ZPAGE)
        } else {
            0
        };
        Self {
            index,
            size,
            objs_per_page,
            nr_zpages: 0,
            obj_count: 0,
        }
    }
}

// -------------------------------------------------------------------
// ZsPage
// -------------------------------------------------------------------

/// A zsmalloc page (spans two physical pages).
#[derive(Debug, Clone, Copy, Default)]
pub struct ZsPage {
    /// First page PFN.
    pub pfn_first: u64,
    /// Second page PFN.
    pub pfn_second: u64,
    /// Size class index.
    pub class_idx: usize,
    /// Number of objects in use.
    pub inuse: usize,
    /// Maximum objects.
    pub max_objects: usize,
    /// Whether this zpage is active.
    pub active: bool,
}

impl ZsPage {
    /// Creates a new zpage.
    pub fn new(pfn_first: u64, pfn_second: u64, class_idx: usize, max_objects: usize) -> Self {
        Self {
            pfn_first,
            pfn_second,
            class_idx,
            inuse: 0,
            max_objects,
            active: true,
        }
    }

    /// Returns `true` if the zpage is full.
    pub fn is_full(&self) -> bool {
        self.inuse >= self.max_objects
    }

    /// Returns `true` if the zpage is empty.
    pub fn is_empty(&self) -> bool {
        self.inuse == 0
    }

    /// Returns the utilization ratio (per-mille).
    pub fn utilization(&self) -> u32 {
        if self.max_objects == 0 {
            return 0;
        }
        ((self.inuse as u64 * 1000) / self.max_objects as u64) as u32
    }
}

// -------------------------------------------------------------------
// ZsHandle
// -------------------------------------------------------------------

/// An opaque handle to an allocated zsmalloc object.
#[derive(Debug, Clone, Copy, Default)]
pub struct ZsHandle {
    /// Zpage index.
    pub zpage_idx: usize,
    /// Object index within the zpage.
    pub obj_idx: usize,
    /// Whether this handle is valid.
    pub valid: bool,
}

// -------------------------------------------------------------------
// ZsPoolStats
// -------------------------------------------------------------------

/// Pool statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct ZsPoolStats {
    /// Total objects allocated.
    pub allocs: u64,
    /// Total objects freed.
    pub frees: u64,
    /// Total zpages allocated.
    pub zpages_alloc: u64,
    /// Total zpages freed.
    pub zpages_freed: u64,
    /// Total bytes stored (object sizes).
    pub bytes_stored: u64,
    /// Allocation failures.
    pub alloc_failures: u64,
    /// Compaction moves.
    pub compact_moves: u64,
}

impl ZsPoolStats {
    /// Returns the memory efficiency (per-mille).
    pub fn efficiency(&self) -> u32 {
        let total_mem = self.zpages_alloc * PAGE_SIZE * 2;
        if total_mem == 0 {
            return 0;
        }
        ((self.bytes_stored * 1000) / total_mem) as u32
    }

    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// ZsPool
// -------------------------------------------------------------------

/// The zsmalloc memory pool.
pub struct ZsPool {
    /// Size classes.
    classes: [SizeClass; NR_SIZE_CLASSES],
    /// Zpages.
    zpages: [ZsPage; MAX_ZPAGES],
    /// Number of zpages.
    zpage_count: usize,
    /// Next PFN for page allocation.
    next_pfn: u64,
    /// Statistics.
    stats: ZsPoolStats,
}

impl Default for ZsPool {
    fn default() -> Self {
        let mut classes = [SizeClass::default(); NR_SIZE_CLASSES];
        for i in 0..NR_SIZE_CLASSES {
            let size = MIN_OBJ_SIZE + i * ((MAX_OBJ_SIZE - MIN_OBJ_SIZE) / NR_SIZE_CLASSES);
            classes[i] = SizeClass::new(i, size);
        }
        Self {
            classes,
            zpages: [ZsPage::default(); MAX_ZPAGES],
            zpage_count: 0,
            next_pfn: 0x4000,
            stats: ZsPoolStats::default(),
        }
    }
}

impl ZsPool {
    /// Creates a new zsmalloc pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Finds the best size class for the given object size.
    fn find_class(&self, size: usize) -> Result<usize> {
        for i in 0..NR_SIZE_CLASSES {
            if self.classes[i].size >= size {
                return Ok(i);
            }
        }
        Err(Error::InvalidArgument)
    }

    /// Allocates an object of the given size.
    pub fn alloc(&mut self, size: usize) -> Result<ZsHandle> {
        if size < MIN_OBJ_SIZE || size > MAX_OBJ_SIZE {
            return Err(Error::InvalidArgument);
        }
        let class_idx = self.find_class(size)?;

        // Find a non-full zpage for this class.
        for i in 0..self.zpage_count {
            if self.zpages[i].active
                && self.zpages[i].class_idx == class_idx
                && !self.zpages[i].is_full()
            {
                let obj_idx = self.zpages[i].inuse;
                self.zpages[i].inuse += 1;
                self.classes[class_idx].obj_count += 1;
                self.stats.allocs += 1;
                self.stats.bytes_stored += size as u64;
                return Ok(ZsHandle {
                    zpage_idx: i,
                    obj_idx,
                    valid: true,
                });
            }
        }

        // Allocate a new zpage.
        if self.zpage_count >= MAX_ZPAGES {
            self.stats.alloc_failures += 1;
            return Err(Error::OutOfMemory);
        }
        let pfn1 = self.next_pfn;
        let pfn2 = self.next_pfn + 1;
        self.next_pfn += 2;

        let zpage_idx = self.zpage_count;
        self.zpages[zpage_idx] =
            ZsPage::new(pfn1, pfn2, class_idx, self.classes[class_idx].objs_per_page);
        self.zpages[zpage_idx].inuse = 1;
        self.zpage_count += 1;
        self.classes[class_idx].nr_zpages += 1;
        self.classes[class_idx].obj_count += 1;
        self.stats.allocs += 1;
        self.stats.zpages_alloc += 1;
        self.stats.bytes_stored += size as u64;

        Ok(ZsHandle {
            zpage_idx,
            obj_idx: 0,
            valid: true,
        })
    }

    /// Frees an object by handle.
    pub fn free(&mut self, handle: ZsHandle) -> Result<()> {
        if !handle.valid || handle.zpage_idx >= self.zpage_count {
            return Err(Error::NotFound);
        }
        let zpage = &mut self.zpages[handle.zpage_idx];
        if !zpage.active || zpage.inuse == 0 {
            return Err(Error::NotFound);
        }
        zpage.inuse -= 1;
        self.stats.frees += 1;

        if zpage.is_empty() {
            zpage.active = false;
            self.stats.zpages_freed += 1;
        }
        Ok(())
    }

    /// Returns the number of zpages.
    pub fn zpage_count(&self) -> usize {
        self.zpage_count
    }

    /// Returns statistics.
    pub fn stats(&self) -> &ZsPoolStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
