// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page reference counting subsystem.
//!
//! Provides fine-grained reference counting for physical pages,
//! including support for compound (multi-order) pages. Reference
//! counts track three distinct dimensions:
//!
//! - **count** — total references (allocator, page cache, direct I/O)
//! - **mapcount** — number of page table entries mapping this page
//! - **pincount** — GUP (get_user_pages) pin count for DMA safety
//!
//! Compound pages (e.g., huge pages) use a bias trick: tail pages
//! share the head page's reference count rather than maintaining
//! independent counts.
//!
//! - [`PageRef`] — per-page reference counts
//! - [`PageRefFlags`] — page state flags
//! - [`CompoundPageRef`] — compound (multi-order) page descriptor
//! - [`PageRefPool`] — pool of 4096 page references
//! - [`PageRefStats`] — aggregate statistics
//!
//! Reference: Linux `include/linux/mm_types.h` — `struct page`,
//! `mm/internal.h` — `page_ref_*()` functions.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of page references in the pool.
const MAX_PAGE_REFS: usize = 4096;

/// Maximum compound page order (2^10 = 1024 pages).
const MAX_COMPOUND_ORDER: u8 = 10;

/// Bias value added to tail page refcounts to detect underflow.
///
/// When a tail page is part of a compound page, its count field is
/// set to `TAIL_BIAS` rather than tracking independently. All real
/// reference operations go through the head page.
const TAIL_BIAS: i32 = -128;

/// Refcount value indicating a free (unallocated) page.
const REFCOUNT_FREE: i32 = 0;

/// Maximum allowed reference count before overflow protection kicks in.
const REFCOUNT_MAX: i32 = i32::MAX / 2;

// -------------------------------------------------------------------
// PageRefFlags
// -------------------------------------------------------------------

/// Flags indicating the state and type of a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageRefFlags(pub u32);

impl PageRefFlags {
    /// Page is the head of a compound page.
    pub const COMPOUND_HEAD: Self = Self(1 << 0);

    /// Page is a tail of a compound page.
    pub const COMPOUND_TAIL: Self = Self(1 << 1);

    /// Page is locked (e.g., for I/O or page table updates).
    pub const PG_LOCKED: Self = Self(1 << 2);

    /// Page is managed by the buddy allocator (free).
    pub const PG_BUDDY: Self = Self(1 << 3);

    /// Page is on an LRU list.
    pub const PG_LRU: Self = Self(1 << 4);

    /// Page is dirty (modified since last writeback).
    pub const PG_DIRTY: Self = Self(1 << 5);

    /// Page is active (recently accessed).
    pub const PG_ACTIVE: Self = Self(1 << 6);

    /// Page is in the swap cache.
    pub const PG_SWAPCACHE: Self = Self(1 << 7);

    /// Page is under writeback.
    pub const PG_WRITEBACK: Self = Self(1 << 8);

    /// Page has been frozen for migration.
    pub const PG_FROZEN: Self = Self(1 << 9);

    /// Empty flags.
    pub const NONE: Self = Self(0);

    /// Check if a specific flag is set.
    pub fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 == flag.0
    }

    /// Set a flag.
    pub fn set(&mut self, flag: Self) {
        self.0 |= flag.0;
    }

    /// Clear a flag.
    pub fn clear(&mut self, flag: Self) {
        self.0 &= !flag.0;
    }

    /// Returns `true` if this page is a compound head.
    pub fn is_compound_head(self) -> bool {
        self.contains(Self::COMPOUND_HEAD)
    }

    /// Returns `true` if this page is a compound tail.
    pub fn is_compound_tail(self) -> bool {
        self.contains(Self::COMPOUND_TAIL)
    }
}

impl Default for PageRefFlags {
    fn default() -> Self {
        Self::NONE
    }
}

// -------------------------------------------------------------------
// PageRef
// -------------------------------------------------------------------

/// Per-page reference counts.
///
/// Tracks three independent reference dimensions for a single
/// physical page frame.
#[derive(Debug, Clone, Copy)]
pub struct PageRef {
    /// Total reference count. A page is free when count == 0.
    pub count: i32,
    /// Number of page table entries mapping this page.
    pub mapcount: i32,
    /// GUP pin count for DMA-safe references.
    pub pincount: i32,
    /// Page state flags.
    pub flags: PageRefFlags,
    /// Page frame number.
    pub pfn: u64,
    /// Whether this slot is allocated (in use).
    pub allocated: bool,
}

impl PageRef {
    /// Creates an empty, unallocated page reference.
    const fn empty() -> Self {
        Self {
            count: REFCOUNT_FREE,
            mapcount: 0,
            pincount: 0,
            flags: PageRefFlags::NONE,
            pfn: 0,
            allocated: false,
        }
    }

    /// Returns `true` if this page has no references.
    pub fn is_free(&self) -> bool {
        self.count == REFCOUNT_FREE && !self.allocated
    }

    /// Returns `true` if this page is shared (refcount > 1).
    pub fn is_shared(&self) -> bool {
        self.count > 1
    }

    /// Returns `true` if this page is mapped in any page table.
    pub fn is_mapped(&self) -> bool {
        self.mapcount > 0
    }

    /// Returns `true` if this page is pinned by GUP.
    pub fn is_pinned(&self) -> bool {
        self.pincount > 0
    }
}

// -------------------------------------------------------------------
// CompoundPageRef
// -------------------------------------------------------------------

/// Descriptor for a compound (multi-order) page.
///
/// A compound page consists of 2^order contiguous physical pages.
/// The first page is the "head" and carries the real reference count;
/// tail pages reference the head.
#[derive(Debug, Clone, Copy)]
pub struct CompoundPageRef {
    /// Index into the PageRefPool for the head page.
    pub head_idx: usize,
    /// Allocation order (number of pages = 2^order).
    pub order: u8,
    /// Number of pages in this compound page.
    pub nr_pages: u32,
    /// Destructor callback identifier (0 = default free).
    pub dtor: u32,
    /// Whether this compound descriptor is active.
    pub active: bool,
}

impl CompoundPageRef {
    /// Creates an empty, inactive compound page descriptor.
    const fn empty() -> Self {
        Self {
            head_idx: 0,
            order: 0,
            nr_pages: 0,
            dtor: 0,
            active: false,
        }
    }
}

/// Maximum number of compound page descriptors.
const MAX_COMPOUNDS: usize = 128;

// -------------------------------------------------------------------
// PageRefOps — trait-like operations
// -------------------------------------------------------------------

/// Increments the reference count of a page.
///
/// Returns the new count, or an error if overflow would occur.
pub fn get_page(page: &mut PageRef) -> Result<i32> {
    if page.count >= REFCOUNT_MAX {
        return Err(Error::InvalidArgument);
    }
    if !page.allocated {
        return Err(Error::NotFound);
    }
    page.count += 1;
    Ok(page.count)
}

/// Decrements the reference count of a page.
///
/// Returns the new count. If the count reaches zero, the caller
/// is responsible for freeing the page.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if count would go below zero.
pub fn put_page(page: &mut PageRef) -> Result<i32> {
    if !page.allocated {
        return Err(Error::NotFound);
    }
    if page.count <= 0 {
        return Err(Error::InvalidArgument);
    }
    page.count -= 1;
    Ok(page.count)
}

/// Attempts to acquire a reference, failing if count is zero.
///
/// This is the "try" variant used when the caller does not know
/// whether the page is still alive.
///
/// # Errors
///
/// Returns [`Error::NotFound`] if the page is not allocated.
/// Returns [`Error::WouldBlock`] if count is already zero.
pub fn try_get_page(page: &mut PageRef) -> Result<i32> {
    if !page.allocated {
        return Err(Error::NotFound);
    }
    if page.count == 0 {
        return Err(Error::WouldBlock);
    }
    if page.count >= REFCOUNT_MAX {
        return Err(Error::InvalidArgument);
    }
    page.count += 1;
    Ok(page.count)
}

/// Returns the current reference count.
pub fn page_count(page: &PageRef) -> i32 {
    page.count
}

/// Returns the current map count.
pub fn page_mapcount(page: &PageRef) -> i32 {
    page.mapcount
}

/// Freezes a page's reference count for migration.
///
/// Sets the PG_FROZEN flag and returns the count at freeze time.
/// While frozen, normal get/put operations should be avoided.
///
/// # Errors
///
/// Returns [`Error::NotFound`] if the page is not allocated.
/// Returns [`Error::Busy`] if the page is already frozen.
pub fn page_ref_freeze(page: &mut PageRef) -> Result<i32> {
    if !page.allocated {
        return Err(Error::NotFound);
    }
    if page.flags.contains(PageRefFlags::PG_FROZEN) {
        return Err(Error::Busy);
    }
    page.flags.set(PageRefFlags::PG_FROZEN);
    Ok(page.count)
}

/// Unfreezes a page's reference count after migration.
///
/// Clears the PG_FROZEN flag.
///
/// # Errors
///
/// Returns [`Error::NotFound`] if the page is not allocated.
/// Returns [`Error::InvalidArgument`] if the page is not frozen.
pub fn page_ref_unfreeze(page: &mut PageRef) -> Result<()> {
    if !page.allocated {
        return Err(Error::NotFound);
    }
    if !page.flags.contains(PageRefFlags::PG_FROZEN) {
        return Err(Error::InvalidArgument);
    }
    page.flags.clear(PageRefFlags::PG_FROZEN);
    Ok(())
}

/// Increments the map count for a page.
///
/// Called when a new page table entry is created for this page.
pub fn page_add_map(page: &mut PageRef) -> Result<i32> {
    if !page.allocated {
        return Err(Error::NotFound);
    }
    page.mapcount += 1;
    Ok(page.mapcount)
}

/// Decrements the map count for a page.
///
/// Called when a page table entry for this page is removed.
pub fn page_remove_map(page: &mut PageRef) -> Result<i32> {
    if !page.allocated {
        return Err(Error::NotFound);
    }
    if page.mapcount <= 0 {
        return Err(Error::InvalidArgument);
    }
    page.mapcount -= 1;
    Ok(page.mapcount)
}

/// Increments the GUP pin count.
pub fn page_pin(page: &mut PageRef) -> Result<i32> {
    if !page.allocated {
        return Err(Error::NotFound);
    }
    page.pincount += 1;
    Ok(page.pincount)
}

/// Decrements the GUP pin count.
pub fn page_unpin(page: &mut PageRef) -> Result<i32> {
    if !page.allocated {
        return Err(Error::NotFound);
    }
    if page.pincount <= 0 {
        return Err(Error::InvalidArgument);
    }
    page.pincount -= 1;
    Ok(page.pincount)
}

// -------------------------------------------------------------------
// PageRefStats
// -------------------------------------------------------------------

/// Aggregate page reference counting statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct PageRefStats {
    /// Total `get_page` operations.
    pub total_gets: u64,
    /// Total `put_page` operations.
    pub total_puts: u64,
    /// Total failed `try_get_page` attempts.
    pub failed_trys: u64,
    /// Total compound page references created.
    pub compound_refs: u64,
    /// Total pages currently allocated.
    pub allocated_pages: u64,
    /// Total freeze operations.
    pub freeze_count: u64,
    /// Total unfreeze operations.
    pub unfreeze_count: u64,
}

// -------------------------------------------------------------------
// PageRefPool
// -------------------------------------------------------------------

/// Pool of page reference descriptors.
///
/// Manages a fixed array of [`PageRef`] entries and provides
/// allocation, deallocation, and reference count operations.
pub struct PageRefPool {
    /// Array of page reference entries.
    pages: [PageRef; MAX_PAGE_REFS],
    /// Number of allocated (in-use) entries.
    allocated_count: usize,
    /// Compound page descriptors.
    compounds: [CompoundPageRef; MAX_COMPOUNDS],
    /// Number of active compound descriptors.
    compound_count: usize,
    /// Statistics.
    total_gets: u64,
    /// Total put operations.
    total_puts: u64,
    /// Total failed try-get operations.
    failed_trys: u64,
    /// Total compound references created.
    compound_refs: u64,
    /// Total freeze operations performed.
    freeze_count: u64,
    /// Total unfreeze operations performed.
    unfreeze_count: u64,
}

impl Default for PageRefPool {
    fn default() -> Self {
        Self::new()
    }
}

impl PageRefPool {
    /// Creates a new empty page reference pool.
    pub const fn new() -> Self {
        Self {
            pages: [PageRef::empty(); MAX_PAGE_REFS],
            allocated_count: 0,
            compounds: [CompoundPageRef::empty(); MAX_COMPOUNDS],
            compound_count: 0,
            total_gets: 0,
            total_puts: 0,
            failed_trys: 0,
            compound_refs: 0,
            freeze_count: 0,
            unfreeze_count: 0,
        }
    }

    /// Allocates a new page reference for the given PFN.
    ///
    /// The page starts with a reference count of 1.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the pool is full.
    pub fn alloc(&mut self, pfn: u64) -> Result<usize> {
        let idx = self.find_free_slot()?;

        self.pages[idx] = PageRef {
            count: 1,
            mapcount: 0,
            pincount: 0,
            flags: PageRefFlags::NONE,
            pfn,
            allocated: true,
        };
        self.allocated_count += 1;
        self.total_gets += 1;

        Ok(idx)
    }

    /// Frees a page reference, returning it to the pool.
    ///
    /// The page's reference count must be zero or one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the index is out of range.
    /// Returns [`Error::Busy`] if the page still has references > 1.
    pub fn free(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_PAGE_REFS || !self.pages[idx].allocated {
            return Err(Error::InvalidArgument);
        }
        if self.pages[idx].count > 1 {
            return Err(Error::Busy);
        }
        if self.pages[idx].mapcount > 0 {
            return Err(Error::Busy);
        }
        if self.pages[idx].pincount > 0 {
            return Err(Error::Busy);
        }

        self.pages[idx] = PageRef::empty();
        self.allocated_count -= 1;

        Ok(())
    }

    /// Increments the reference count of the page at `idx`.
    ///
    /// # Errors
    ///
    /// Returns errors from [`get_page`].
    pub fn get(&mut self, idx: usize) -> Result<i32> {
        if idx >= MAX_PAGE_REFS {
            return Err(Error::InvalidArgument);
        }

        // For compound tails, redirect to the head.
        if self.pages[idx].flags.is_compound_tail() {
            let head_idx = self.find_compound_head(idx)?;
            let result = get_page(&mut self.pages[head_idx]);
            if result.is_ok() {
                self.total_gets += 1;
            }
            return result;
        }

        let result = get_page(&mut self.pages[idx]);
        if result.is_ok() {
            self.total_gets += 1;
        }
        result
    }

    /// Decrements the reference count of the page at `idx`.
    ///
    /// # Errors
    ///
    /// Returns errors from [`put_page`].
    pub fn put(&mut self, idx: usize) -> Result<i32> {
        if idx >= MAX_PAGE_REFS {
            return Err(Error::InvalidArgument);
        }

        // For compound tails, redirect to the head.
        if self.pages[idx].flags.is_compound_tail() {
            let head_idx = self.find_compound_head(idx)?;
            let result = put_page(&mut self.pages[head_idx]);
            if result.is_ok() {
                self.total_puts += 1;
            }
            return result;
        }

        let result = put_page(&mut self.pages[idx]);
        if result.is_ok() {
            self.total_puts += 1;
        }
        result
    }

    /// Attempts to acquire a reference, failing if count is zero.
    ///
    /// # Errors
    ///
    /// Returns errors from [`try_get_page`].
    pub fn try_get(&mut self, idx: usize) -> Result<i32> {
        if idx >= MAX_PAGE_REFS {
            return Err(Error::InvalidArgument);
        }

        let result = try_get_page(&mut self.pages[idx]);
        match &result {
            Ok(_) => {
                self.total_gets += 1;
            }
            Err(_) => {
                self.failed_trys += 1;
            }
        }
        result
    }

    /// Freezes a page for migration.
    ///
    /// # Errors
    ///
    /// Returns errors from [`page_ref_freeze`].
    pub fn freeze(&mut self, idx: usize) -> Result<i32> {
        if idx >= MAX_PAGE_REFS {
            return Err(Error::InvalidArgument);
        }
        let result = page_ref_freeze(&mut self.pages[idx]);
        if result.is_ok() {
            self.freeze_count += 1;
        }
        result
    }

    /// Unfreezes a page after migration.
    ///
    /// # Errors
    ///
    /// Returns errors from [`page_ref_unfreeze`].
    pub fn unfreeze(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_PAGE_REFS {
            return Err(Error::InvalidArgument);
        }
        let result = page_ref_unfreeze(&mut self.pages[idx]);
        if result.is_ok() {
            self.unfreeze_count += 1;
        }
        result
    }

    /// Creates a compound page starting at `head_idx` with the given order.
    ///
    /// Marks the head page with COMPOUND_HEAD and all tail pages with
    /// COMPOUND_TAIL. Tail pages have their count set to TAIL_BIAS.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the order is too large.
    /// Returns [`Error::OutOfMemory`] if there is no room for the compound
    /// descriptor or if insufficient consecutive pages are free.
    pub fn create_compound(&mut self, head_idx: usize, order: u8) -> Result<usize> {
        if order > MAX_COMPOUND_ORDER {
            return Err(Error::InvalidArgument);
        }
        if self.compound_count >= MAX_COMPOUNDS {
            return Err(Error::OutOfMemory);
        }

        let nr_pages = 1_u32 << order;
        let end_idx = head_idx + nr_pages as usize;

        if end_idx > MAX_PAGE_REFS {
            return Err(Error::OutOfMemory);
        }

        // Verify all pages in range are allocated.
        for i in head_idx..end_idx {
            if !self.pages[i].allocated {
                return Err(Error::InvalidArgument);
            }
        }

        // Mark head page.
        self.pages[head_idx].flags.set(PageRefFlags::COMPOUND_HEAD);

        // Mark tail pages with bias.
        for i in (head_idx + 1)..end_idx {
            self.pages[i].flags.set(PageRefFlags::COMPOUND_TAIL);
            self.pages[i].count = TAIL_BIAS;
        }

        // Record compound descriptor.
        let comp_idx = self.compound_count;
        self.compounds[comp_idx] = CompoundPageRef {
            head_idx,
            order,
            nr_pages,
            dtor: 0,
            active: true,
        };
        self.compound_count += 1;
        self.compound_refs += 1;

        Ok(comp_idx)
    }

    /// Destroys a compound page, restoring individual page references.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the compound index is invalid.
    pub fn destroy_compound(&mut self, comp_idx: usize) -> Result<()> {
        if comp_idx >= self.compound_count || !self.compounds[comp_idx].active {
            return Err(Error::InvalidArgument);
        }

        let head_idx = self.compounds[comp_idx].head_idx;
        let nr_pages = self.compounds[comp_idx].nr_pages as usize;
        let end_idx = head_idx + nr_pages;

        // Clear head flag.
        if head_idx < MAX_PAGE_REFS {
            self.pages[head_idx]
                .flags
                .clear(PageRefFlags::COMPOUND_HEAD);
        }

        // Clear tail flags and restore refcounts.
        for i in (head_idx + 1)..end_idx {
            if i < MAX_PAGE_REFS {
                self.pages[i].flags.clear(PageRefFlags::COMPOUND_TAIL);
                self.pages[i].count = 1;
            }
        }

        self.compounds[comp_idx].active = false;
        Ok(())
    }

    /// Returns a reference to the page at `idx`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the index is out of range.
    pub fn page(&self, idx: usize) -> Result<&PageRef> {
        if idx >= MAX_PAGE_REFS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.pages[idx])
    }

    /// Returns the number of allocated pages.
    pub fn allocated_count(&self) -> usize {
        self.allocated_count
    }

    /// Returns the number of active compound pages.
    pub fn compound_count(&self) -> usize {
        self.compound_count
    }

    /// Returns the total capacity of the pool.
    pub fn capacity(&self) -> usize {
        MAX_PAGE_REFS
    }

    /// Returns aggregate statistics.
    pub fn stats(&self) -> PageRefStats {
        PageRefStats {
            total_gets: self.total_gets,
            total_puts: self.total_puts,
            failed_trys: self.failed_trys,
            compound_refs: self.compound_refs,
            allocated_pages: self.allocated_count as u64,
            freeze_count: self.freeze_count,
            unfreeze_count: self.unfreeze_count,
        }
    }

    /// Finds the compound head for a tail page.
    fn find_compound_head(&self, tail_idx: usize) -> Result<usize> {
        for i in 0..self.compound_count {
            if !self.compounds[i].active {
                continue;
            }
            let head = self.compounds[i].head_idx;
            let end = head + self.compounds[i].nr_pages as usize;
            if tail_idx > head && tail_idx < end {
                return Ok(head);
            }
        }
        Err(Error::NotFound)
    }

    /// Finds the first free slot in the page array.
    fn find_free_slot(&self) -> Result<usize> {
        for i in 0..MAX_PAGE_REFS {
            if !self.pages[i].allocated {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }
}
