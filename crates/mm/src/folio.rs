// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Folio abstraction — multi-page memory management unit.
//!
//! A folio is a contiguous, naturally-aligned, power-of-two group of
//! pages. It replaces the old "compound page" concept, providing a
//! cleaner API for managing memory in units larger than a single 4 KiB
//! page without the ambiguity of `struct page` tail pages.
//!
//! # Orders
//!
//! The folio order determines its size:
//! - Order 0: 1 page  (4 KiB)
//! - Order 1: 2 pages (8 KiB)
//! - ...
//! - Order 9: 512 pages (2 MiB) — matches x86_64 huge page
//!
//! # Subsystems
//!
//! - [`FolioOrder`] — type-safe order (0..9)
//! - [`FolioFlags`] — bitflags for folio state
//! - [`Folio`] — core folio descriptor
//! - [`FolioAllocator`] — order-segregated free-list allocator
//! - [`FolioStats`] — per-order allocation statistics
//!
//! Reference: Linux `include/linux/page-flags.h`,
//! `mm/folio-compat.c`, `mm/filemap.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum folio order (2 MiB = 512 pages = order 9).
const MAX_ORDER: usize = 10; // orders 0..9 inclusive

/// Maximum number of folios managed by the allocator.
const MAX_FOLIOS: usize = 2048;

/// Maximum folios per free list (per order).
const MAX_FREE_PER_ORDER: usize = 256;

/// Invalid folio index sentinel.
const INVALID_INDEX: u32 = u32::MAX;

// -------------------------------------------------------------------
// FolioOrder
// -------------------------------------------------------------------

/// Type-safe folio order (0 through 9).
///
/// Order `n` means the folio contains `2^n` pages and is
/// `4096 * 2^n` bytes in size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct FolioOrder(u8);

impl FolioOrder {
    /// Order 0: single 4 KiB page.
    pub const ORDER_0: Self = Self(0);
    /// Order 1: 8 KiB (2 pages).
    pub const ORDER_1: Self = Self(1);
    /// Order 2: 16 KiB (4 pages).
    pub const ORDER_2: Self = Self(2);
    /// Order 3: 32 KiB (8 pages).
    pub const ORDER_3: Self = Self(3);
    /// Order 4: 64 KiB (16 pages).
    pub const ORDER_4: Self = Self(4);
    /// Order 5: 128 KiB (32 pages).
    pub const ORDER_5: Self = Self(5);
    /// Order 6: 256 KiB (64 pages).
    pub const ORDER_6: Self = Self(6);
    /// Order 7: 512 KiB (128 pages).
    pub const ORDER_7: Self = Self(7);
    /// Order 8: 1 MiB (256 pages).
    pub const ORDER_8: Self = Self(8);
    /// Order 9: 2 MiB (512 pages).
    pub const ORDER_9: Self = Self(9);

    /// Create a new order, returning `Err` if `val > 9`.
    pub const fn new(val: u8) -> Result<Self> {
        if val as usize >= MAX_ORDER {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(val))
    }

    /// Raw order value.
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Number of pages in a folio of this order.
    pub const fn nr_pages(self) -> u32 {
        1u32 << self.0
    }

    /// Size in bytes of a folio of this order.
    pub const fn size_bytes(self) -> u64 {
        PAGE_SIZE << self.0
    }
}

// -------------------------------------------------------------------
// FolioFlags
// -------------------------------------------------------------------

/// Bitflags describing the state of a folio.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FolioFlags(u32);

impl FolioFlags {
    /// Folio has been accessed recently.
    pub const REFERENCED: Self = Self(1 << 0);
    /// Folio contents are up-to-date with backing store.
    pub const UPTODATE: Self = Self(1 << 1);
    /// Folio has been modified since last writeback.
    pub const DIRTY: Self = Self(1 << 2);
    /// Folio is on an LRU list.
    pub const LRU: Self = Self(1 << 3);
    /// Folio is on the active LRU list.
    pub const ACTIVE: Self = Self(1 << 4);
    /// Folio was recently part of the working set.
    pub const WORKINGSET: Self = Self(1 << 5);
    /// Folio is locked for exclusive access.
    pub const LOCKED: Self = Self(1 << 6);
    /// Folio is being written back to storage.
    pub const WRITEBACK: Self = Self(1 << 7);
    /// Folio is a candidate for reclaim.
    pub const RECLAIM: Self = Self(1 << 8);
    /// Folio is in the swap cache.
    pub const SWAPCACHE: Self = Self(1 << 9);
    /// Folio has private filesystem data attached.
    pub const PRIVATE: Self = Self(1 << 10);

    /// Empty flag set.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Combine two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Remove flags.
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Test whether specific flags are all set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

// -------------------------------------------------------------------
// Folio
// -------------------------------------------------------------------

/// A folio: a contiguous, power-of-two group of pages.
#[derive(Debug, Clone, Copy)]
pub struct Folio {
    /// Physical base address (naturally aligned to order).
    phys_addr: u64,
    /// Folio order (determines size).
    order: FolioOrder,
    /// State flags.
    flags: FolioFlags,
    /// Reference count (number of users holding a reference).
    ref_count: u32,
    /// Map count (number of page-table mappings).
    map_count: u32,
    /// Identifier of the associated address-space / mapping.
    mapping_id: u32,
    /// Page-cache index within the mapping.
    index: u64,
    /// Whether this folio slot is in use.
    active: bool,
}

impl Folio {
    /// Create an empty (inactive) folio descriptor.
    const fn empty() -> Self {
        Self {
            phys_addr: 0,
            order: FolioOrder::ORDER_0,
            flags: FolioFlags::empty(),
            ref_count: 0,
            map_count: 0,
            mapping_id: 0,
            index: 0,
            active: false,
        }
    }

    /// Physical base address.
    pub const fn phys_addr(&self) -> u64 {
        self.phys_addr
    }

    /// Folio order.
    pub const fn order(&self) -> FolioOrder {
        self.order
    }

    /// Current flags.
    pub const fn flags(&self) -> FolioFlags {
        self.flags
    }

    /// Reference count.
    pub const fn ref_count(&self) -> u32 {
        self.ref_count
    }

    /// Map count.
    pub const fn map_count(&self) -> u32 {
        self.map_count
    }

    /// Mapping identifier.
    pub const fn mapping_id(&self) -> u32 {
        self.mapping_id
    }

    /// Page-cache index.
    pub const fn index(&self) -> u64 {
        self.index
    }

    /// Whether this slot is in use.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Number of pages in this folio.
    pub const fn nr_pages(&self) -> u32 {
        self.order.nr_pages()
    }

    /// Size in bytes.
    pub const fn size_bytes(&self) -> u64 {
        self.order.size_bytes()
    }
}

impl Default for Folio {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// FolioFreeList (per-order)
// -------------------------------------------------------------------

/// Per-order free list of available folios (stored as folio indices).
struct FolioFreeList {
    /// Indices into the allocator's folio array.
    entries: [u32; MAX_FREE_PER_ORDER],
    /// Number of entries in the free list.
    count: u32,
}

impl FolioFreeList {
    /// Create an empty free list.
    const fn empty() -> Self {
        Self {
            entries: [INVALID_INDEX; MAX_FREE_PER_ORDER],
            count: 0,
        }
    }

    /// Push a folio index onto the free list.
    fn push(&mut self, idx: u32) -> Result<()> {
        if self.count as usize >= MAX_FREE_PER_ORDER {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count as usize] = idx;
        self.count += 1;
        Ok(())
    }

    /// Pop a folio index from the free list.
    fn pop(&mut self) -> Option<u32> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        let idx = self.entries[self.count as usize];
        self.entries[self.count as usize] = INVALID_INDEX;
        Some(idx)
    }

    /// Number of entries in the list.
    const fn len(&self) -> u32 {
        self.count
    }
}

// -------------------------------------------------------------------
// FolioStats
// -------------------------------------------------------------------

/// Per-order and aggregate folio allocation statistics.
pub struct FolioStats {
    /// Allocations per order.
    pub per_order_alloc: [u64; MAX_ORDER],
    /// Frees per order.
    pub per_order_free: [u64; MAX_ORDER],
    /// Total dirty folios.
    pub total_dirty: u64,
    /// Total locked folios.
    pub total_locked: u64,
    /// Total active folios.
    pub total_active: u64,
}

impl FolioStats {
    /// Create zeroed statistics.
    const fn new() -> Self {
        Self {
            per_order_alloc: [0; MAX_ORDER],
            per_order_free: [0; MAX_ORDER],
            total_dirty: 0,
            total_locked: 0,
            total_active: 0,
        }
    }
}

impl Default for FolioStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// FolioAllocator
// -------------------------------------------------------------------

/// Order-segregated folio allocator.
///
/// Maintains a pool of folio descriptors and per-order free lists.
/// Supports allocation, freeing, and state management operations.
pub struct FolioAllocator {
    /// All folio descriptors.
    folios: [Folio; MAX_FOLIOS],
    /// Per-order free lists.
    free_lists: [FolioFreeList; MAX_ORDER],
    /// Next physical address to hand out (bump allocator for
    /// simplicity; real implementation backs onto frame allocator).
    next_phys: u64,
    /// Statistics.
    stats: FolioStats,
}

impl FolioAllocator {
    /// Create a new allocator.
    ///
    /// `base_phys` is the starting physical address for the managed
    /// region.
    pub const fn new(base_phys: u64) -> Self {
        Self {
            folios: [const { Folio::empty() }; MAX_FOLIOS],
            free_lists: [const { FolioFreeList::empty() }; MAX_ORDER],
            next_phys: base_phys,
            stats: FolioStats::new(),
        }
    }

    /// Return current statistics.
    pub const fn stats(&self) -> &FolioStats {
        &self.stats
    }

    /// Allocate a folio of the given order.
    ///
    /// Returns the index into the internal folio array on success.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — order is out of range
    /// * `OutOfMemory` — no free folio slots
    pub fn alloc_folio(&mut self, order: FolioOrder) -> Result<u32> {
        let ord = order.value() as usize;
        if ord >= MAX_ORDER {
            return Err(Error::InvalidArgument);
        }

        // Try to reuse a folio from the per-order free list.
        if let Some(idx) = self.free_lists[ord].pop() {
            self.init_folio(idx, order)?;
            self.stats.per_order_alloc[ord] += 1;
            return Ok(idx);
        }

        // Allocate a fresh slot.
        let idx = self.find_free_slot().ok_or(Error::OutOfMemory)?;
        let idx32 = idx as u32;

        // Assign physical address (aligned to order).
        let alignment = order.size_bytes();
        let aligned = (self.next_phys + alignment - 1) & !(alignment - 1);
        self.folios[idx].phys_addr = aligned;
        self.next_phys = aligned + alignment;

        self.init_folio(idx32, order)?;
        self.stats.per_order_alloc[ord] += 1;
        Ok(idx32)
    }

    /// Free a folio by index, returning it to the per-order free list.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — index out of range
    /// * `NotFound` — folio is not active
    pub fn free_folio(&mut self, idx: u32) -> Result<()> {
        if idx as usize >= MAX_FOLIOS {
            return Err(Error::InvalidArgument);
        }
        let i = idx as usize;
        if !self.folios[i].active {
            return Err(Error::NotFound);
        }

        let ord = self.folios[i].order.value() as usize;

        // Update stats before clearing.
        if self.folios[i].flags.contains(FolioFlags::DIRTY) {
            self.stats.total_dirty = self.stats.total_dirty.saturating_sub(1);
        }
        if self.folios[i].flags.contains(FolioFlags::LOCKED) {
            self.stats.total_locked = self.stats.total_locked.saturating_sub(1);
        }

        self.folios[i].active = false;
        self.folios[i].ref_count = 0;
        self.folios[i].map_count = 0;
        self.folios[i].flags = FolioFlags::empty();

        self.stats.per_order_free[ord] += 1;
        self.stats.total_active = self.stats.total_active.saturating_sub(1);

        // Return to free list (best-effort; ignore if full).
        let _ = self.free_lists[ord].push(idx);
        Ok(())
    }

    /// Get an immutable reference to a folio by index.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — index out of range
    /// * `NotFound` — folio is not active
    pub fn get_folio(&self, idx: u32) -> Result<&Folio> {
        if idx as usize >= MAX_FOLIOS {
            return Err(Error::InvalidArgument);
        }
        if !self.folios[idx as usize].active {
            return Err(Error::NotFound);
        }
        Ok(&self.folios[idx as usize])
    }

    // ---------------------------------------------------------------
    // Folio operations
    // ---------------------------------------------------------------

    /// Lock a folio for exclusive access.
    ///
    /// # Errors
    ///
    /// * `Busy` — folio is already locked
    pub fn folio_lock(&mut self, idx: u32) -> Result<()> {
        let folio = self.get_folio_mut(idx)?;
        if folio.flags.contains(FolioFlags::LOCKED) {
            return Err(Error::Busy);
        }
        folio.flags = folio.flags.union(FolioFlags::LOCKED);
        self.stats.total_locked += 1;
        Ok(())
    }

    /// Unlock a folio.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — folio is not locked
    pub fn folio_unlock(&mut self, idx: u32) -> Result<()> {
        let folio = self.get_folio_mut(idx)?;
        if !folio.flags.contains(FolioFlags::LOCKED) {
            return Err(Error::InvalidArgument);
        }
        folio.flags = folio.flags.difference(FolioFlags::LOCKED);
        self.stats.total_locked = self.stats.total_locked.saturating_sub(1);
        Ok(())
    }

    /// Mark a folio dirty.
    pub fn folio_mark_dirty(&mut self, idx: u32) -> Result<()> {
        let folio = self.get_folio_mut(idx)?;
        if !folio.flags.contains(FolioFlags::DIRTY) {
            folio.flags = folio.flags.union(FolioFlags::DIRTY);
            self.stats.total_dirty += 1;
        }
        Ok(())
    }

    /// Clear the dirty flag on a folio.
    pub fn folio_clear_dirty(&mut self, idx: u32) -> Result<()> {
        let folio = self.get_folio_mut(idx)?;
        if folio.flags.contains(FolioFlags::DIRTY) {
            folio.flags = folio.flags.difference(FolioFlags::DIRTY);
            self.stats.total_dirty = self.stats.total_dirty.saturating_sub(1);
        }
        Ok(())
    }

    /// Mark a folio as up-to-date.
    pub fn folio_mark_uptodate(&mut self, idx: u32) -> Result<()> {
        let folio = self.get_folio_mut(idx)?;
        folio.flags = folio.flags.union(FolioFlags::UPTODATE);
        Ok(())
    }

    /// Activate a folio (move to active LRU).
    pub fn folio_activate(&mut self, idx: u32) -> Result<()> {
        let folio = self.get_folio_mut(idx)?;
        folio.flags = folio.flags.union(FolioFlags::ACTIVE);
        folio.flags = folio.flags.union(FolioFlags::LRU);
        folio.flags = folio.flags.union(FolioFlags::REFERENCED);
        Ok(())
    }

    /// Deactivate a folio (move to inactive LRU).
    pub fn folio_deactivate(&mut self, idx: u32) -> Result<()> {
        let folio = self.get_folio_mut(idx)?;
        folio.flags = folio.flags.difference(FolioFlags::ACTIVE);
        folio.flags = folio.flags.difference(FolioFlags::REFERENCED);
        Ok(())
    }

    /// Mark a folio as recently referenced.
    pub fn folio_referenced(&mut self, idx: u32) -> Result<()> {
        let folio = self.get_folio_mut(idx)?;
        folio.flags = folio.flags.union(FolioFlags::REFERENCED);
        Ok(())
    }

    /// Increment the reference count.
    pub fn folio_get(&mut self, idx: u32) -> Result<()> {
        let folio = self.get_folio_mut(idx)?;
        folio.ref_count = folio.ref_count.saturating_add(1);
        Ok(())
    }

    /// Decrement the reference count. If it reaches zero, free the
    /// folio.
    pub fn folio_put(&mut self, idx: u32) -> Result<()> {
        let folio = self.get_folio_mut(idx)?;
        if folio.ref_count == 0 {
            return Err(Error::InvalidArgument);
        }
        folio.ref_count -= 1;
        if folio.ref_count == 0 {
            return self.free_folio(idx);
        }
        Ok(())
    }

    /// Set the mapping for a folio.
    pub fn folio_set_mapping(&mut self, idx: u32, mapping_id: u32, index: u64) -> Result<()> {
        let folio = self.get_folio_mut(idx)?;
        folio.mapping_id = mapping_id;
        folio.index = index;
        Ok(())
    }

    /// Increment the map count (a new page-table mapping was added).
    pub fn folio_map(&mut self, idx: u32) -> Result<()> {
        let folio = self.get_folio_mut(idx)?;
        folio.map_count = folio.map_count.saturating_add(1);
        Ok(())
    }

    /// Decrement the map count.
    pub fn folio_unmap(&mut self, idx: u32) -> Result<()> {
        let folio = self.get_folio_mut(idx)?;
        if folio.map_count == 0 {
            return Err(Error::InvalidArgument);
        }
        folio.map_count -= 1;
        Ok(())
    }

    /// Number of free folios per order.
    pub fn free_count_per_order(&self) -> [u32; MAX_ORDER] {
        let mut counts = [0u32; MAX_ORDER];
        for (i, fl) in self.free_lists.iter().enumerate() {
            counts[i] = fl.len();
        }
        counts
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Find a free folio slot.
    fn find_free_slot(&self) -> Option<usize> {
        self.folios.iter().position(|f| !f.active)
    }

    /// Get a mutable reference to an active folio.
    fn get_folio_mut(&mut self, idx: u32) -> Result<&mut Folio> {
        if idx as usize >= MAX_FOLIOS {
            return Err(Error::InvalidArgument);
        }
        if !self.folios[idx as usize].active {
            return Err(Error::NotFound);
        }
        Ok(&mut self.folios[idx as usize])
    }

    /// Initialise a folio descriptor at the given slot.
    fn init_folio(&mut self, idx: u32, order: FolioOrder) -> Result<()> {
        if idx as usize >= MAX_FOLIOS {
            return Err(Error::InvalidArgument);
        }
        let f = &mut self.folios[idx as usize];
        f.order = order;
        f.flags = FolioFlags::empty();
        f.ref_count = 1;
        f.map_count = 0;
        f.mapping_id = 0;
        f.index = 0;
        f.active = true;
        self.stats.total_active += 1;
        Ok(())
    }
}

impl Default for FolioAllocator {
    fn default() -> Self {
        Self::new(0)
    }
}

// -------------------------------------------------------------------
// Free-standing helpers
// -------------------------------------------------------------------

/// Return the number of pages in a folio of the given order.
pub const fn folio_nr_pages(order: FolioOrder) -> u32 {
    order.nr_pages()
}

/// Return the size in bytes of a folio of the given order.
pub const fn folio_size(order: FolioOrder) -> u64 {
    order.size_bytes()
}
