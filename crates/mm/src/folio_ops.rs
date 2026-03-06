// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Folio operations and management.
//!
//! A folio is a group of contiguous pages managed as a single unit.
//! This module provides operations for creating, splitting, and
//! manipulating folios, including reference counting and LRU placement.
//!
//! # Design
//!
//! ```text
//!  folio_alloc(order)
//!       │
//!       ├─ allocate 2^order contiguous pages
//!       ├─ initialise FolioDescriptor
//!       └─ add to LRU
//!
//!  folio_split(folio, target_order)
//!       │
//!       └─ split into smaller folios
//! ```
//!
//! # Key Types
//!
//! - [`FolioDescriptor`] — metadata for a folio
//! - [`FolioFlags`] — status flags
//! - [`FolioPool`] — pool of folio descriptors
//!
//! Reference: Linux `mm/folio-compat.c`, `include/linux/mm_types.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum folio order (2^MAX_ORDER pages).
const MAX_ORDER: u8 = 10;

/// Maximum folios tracked.
const MAX_FOLIOS: usize = 2048;

/// Page size.
const PAGE_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// FolioFlags
// -------------------------------------------------------------------

/// Status flags for a folio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FolioFlags(u32);

impl FolioFlags {
    /// Folio is on the active LRU list.
    pub const ACTIVE: Self = Self(1 << 0);
    /// Folio has been referenced recently.
    pub const REFERENCED: Self = Self(1 << 1);
    /// Folio is dirty.
    pub const DIRTY: Self = Self(1 << 2);
    /// Folio is locked.
    pub const LOCKED: Self = Self(1 << 3);
    /// Folio is under writeback.
    pub const WRITEBACK: Self = Self(1 << 4);
    /// Folio is mapped in at least one page table.
    pub const MAPPED: Self = Self(1 << 5);
    /// Folio is unevictable (mlocked).
    pub const UNEVICTABLE: Self = Self(1 << 6);
    /// Large folio (order > 0).
    pub const LARGE: Self = Self(1 << 7);

    /// Empty flags.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Check whether a flag is set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Set a flag.
    pub const fn set(self, flag: Self) -> Self {
        Self(self.0 | flag.0)
    }

    /// Clear a flag.
    pub const fn clear(self, flag: Self) -> Self {
        Self(self.0 & !flag.0)
    }

    /// Return raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl Default for FolioFlags {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// FolioDescriptor
// -------------------------------------------------------------------

/// Metadata for a folio (contiguous page group).
#[derive(Debug, Clone, Copy)]
pub struct FolioDescriptor {
    /// Base PFN of the folio.
    base_pfn: u64,
    /// Order (folio spans 2^order pages).
    order: u8,
    /// Reference count.
    refcount: u32,
    /// Map count (number of page table mappings).
    mapcount: u32,
    /// Status flags.
    flags: FolioFlags,
    /// Owning memory cgroup ID.
    memcg_id: u32,
    /// Whether this descriptor is in use.
    in_use: bool,
}

impl FolioDescriptor {
    /// Create a new folio descriptor.
    pub const fn new(base_pfn: u64, order: u8) -> Self {
        let flags = if order > 0 {
            FolioFlags(FolioFlags::LARGE.0)
        } else {
            FolioFlags::empty()
        };
        Self {
            base_pfn,
            order,
            refcount: 1,
            mapcount: 0,
            flags,
            memcg_id: 0,
            in_use: true,
        }
    }

    /// Return the base PFN.
    pub const fn base_pfn(&self) -> u64 {
        self.base_pfn
    }

    /// Return the order.
    pub const fn order(&self) -> u8 {
        self.order
    }

    /// Return the number of pages in this folio.
    pub const fn nr_pages(&self) -> u64 {
        1u64 << self.order
    }

    /// Return the size in bytes.
    pub const fn size(&self) -> u64 {
        self.nr_pages() * PAGE_SIZE
    }

    /// Return the reference count.
    pub const fn refcount(&self) -> u32 {
        self.refcount
    }

    /// Increment the reference count.
    pub fn get_ref(&mut self) {
        self.refcount = self.refcount.saturating_add(1);
    }

    /// Decrement the reference count. Returns true if dropped to zero.
    pub fn put_ref(&mut self) -> bool {
        self.refcount = self.refcount.saturating_sub(1);
        self.refcount == 0
    }

    /// Return the map count.
    pub const fn mapcount(&self) -> u32 {
        self.mapcount
    }

    /// Increment map count.
    pub fn map(&mut self) {
        self.mapcount = self.mapcount.saturating_add(1);
        self.flags = self.flags.set(FolioFlags::MAPPED);
    }

    /// Decrement map count.
    pub fn unmap(&mut self) {
        self.mapcount = self.mapcount.saturating_sub(1);
        if self.mapcount == 0 {
            self.flags = self.flags.clear(FolioFlags::MAPPED);
        }
    }

    /// Return the flags.
    pub const fn flags(&self) -> FolioFlags {
        self.flags
    }

    /// Set a flag.
    pub fn set_flag(&mut self, flag: FolioFlags) {
        self.flags = self.flags.set(flag);
    }

    /// Clear a flag.
    pub fn clear_flag(&mut self, flag: FolioFlags) {
        self.flags = self.flags.clear(flag);
    }

    /// Mark the folio dirty.
    pub fn mark_dirty(&mut self) {
        self.set_flag(FolioFlags::DIRTY);
    }

    /// Clear the dirty flag.
    pub fn clear_dirty(&mut self) {
        self.clear_flag(FolioFlags::DIRTY);
    }

    /// Check whether the folio is a large folio.
    pub const fn is_large(&self) -> bool {
        self.order > 0
    }

    /// Set the owning memcg.
    pub fn set_memcg(&mut self, memcg_id: u32) {
        self.memcg_id = memcg_id;
    }

    /// Return the memcg ID.
    pub const fn memcg_id(&self) -> u32 {
        self.memcg_id
    }

    /// Whether this descriptor is in use.
    pub const fn is_in_use(&self) -> bool {
        self.in_use
    }

    /// Release this descriptor.
    pub fn release(&mut self) {
        self.in_use = false;
    }
}

impl Default for FolioDescriptor {
    fn default() -> Self {
        Self {
            base_pfn: 0,
            order: 0,
            refcount: 0,
            mapcount: 0,
            flags: FolioFlags::empty(),
            memcg_id: 0,
            in_use: false,
        }
    }
}

// -------------------------------------------------------------------
// FolioPool
// -------------------------------------------------------------------

/// Pool of folio descriptors.
pub struct FolioPool {
    /// Folio descriptors.
    folios: [FolioDescriptor; MAX_FOLIOS],
    /// Number of active folios.
    active_count: usize,
    /// Total pages managed.
    total_pages: u64,
    /// Next PFN to allocate from (simplified).
    next_pfn: u64,
}

impl FolioPool {
    /// Create a new pool.
    pub const fn new() -> Self {
        Self {
            folios: [const {
                FolioDescriptor {
                    base_pfn: 0,
                    order: 0,
                    refcount: 0,
                    mapcount: 0,
                    flags: FolioFlags::empty(),
                    memcg_id: 0,
                    in_use: false,
                }
            }; MAX_FOLIOS],
            active_count: 0,
            total_pages: 0,
            next_pfn: 0x1000,
        }
    }

    /// Return the number of active folios.
    pub const fn active_count(&self) -> usize {
        self.active_count
    }

    /// Return total pages managed.
    pub const fn total_pages(&self) -> u64 {
        self.total_pages
    }

    /// Allocate a folio of the given order.
    pub fn alloc(&mut self, order: u8) -> Result<usize> {
        if order > MAX_ORDER {
            return Err(Error::InvalidArgument);
        }
        if self.active_count >= MAX_FOLIOS {
            return Err(Error::OutOfMemory);
        }
        let nr_pages = 1u64 << order;
        let pfn = self.next_pfn;
        self.next_pfn += nr_pages;

        let idx = self.active_count;
        self.folios[idx] = FolioDescriptor::new(pfn, order);
        self.active_count += 1;
        self.total_pages += nr_pages;

        Ok(idx)
    }

    /// Get a folio by index.
    pub fn get(&self, idx: usize) -> Option<&FolioDescriptor> {
        if idx < self.active_count && self.folios[idx].is_in_use() {
            Some(&self.folios[idx])
        } else {
            None
        }
    }

    /// Get a mutable folio by index.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut FolioDescriptor> {
        if idx < self.active_count && self.folios[idx].is_in_use() {
            Some(&mut self.folios[idx])
        } else {
            None
        }
    }

    /// Release a folio by index.
    pub fn release(&mut self, idx: usize) -> Result<()> {
        if idx >= self.active_count {
            return Err(Error::NotFound);
        }
        let nr_pages = self.folios[idx].nr_pages();
        self.folios[idx].release();
        self.total_pages = self.total_pages.saturating_sub(nr_pages);
        Ok(())
    }
}

impl Default for FolioPool {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Allocate a single-page folio (order 0).
pub fn alloc_folio_single(pool: &mut FolioPool) -> Result<usize> {
    pool.alloc(0)
}

/// Allocate a large folio.
pub fn alloc_folio_large(pool: &mut FolioPool, order: u8) -> Result<usize> {
    if order == 0 {
        return Err(Error::InvalidArgument);
    }
    pool.alloc(order)
}

/// Mark a folio as referenced (for LRU promotion).
pub fn folio_mark_accessed(pool: &mut FolioPool, idx: usize) -> Result<()> {
    let folio = pool.get_mut(idx).ok_or(Error::NotFound)?;
    folio.set_flag(FolioFlags::REFERENCED);
    Ok(())
}
