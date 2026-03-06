// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Compound page management.
//!
//! A compound page is a group of contiguous physical pages treated
//! as a single higher-order allocation. The first page is the
//! **head page** and all subsequent pages are **tail pages** that
//! point back to the head.
//!
//! Compound pages are used for huge pages, transparent huge pages,
//! and any allocation larger than a single 4 KiB page.
//!
//! # Subsystems
//!
//! - [`CompoundPageDtor`] — destructor type for compound pages
//! - [`CompoundPage`] — descriptor for a compound page group
//! - [`CompoundPageManager`] — allocator/tracker for compound pages
//! - [`CompoundPageStats`] — allocation statistics
//!
//! Reference: Linux `include/linux/mm.h`, `mm/page_alloc.c`,
//! `include/linux/page-flags.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum supported compound page order (order 0..MAX_COMPOUND_ORDER-1).
/// Order 9 = 512 pages = 2 MiB, order 10 = 1024 pages = 4 MiB.
const MAX_COMPOUND_ORDER: u8 = 11;

/// Maximum number of compound pages tracked by the manager.
const MAX_COMPOUND_PAGES: usize = 512;

/// Maximum number of sub-pages in the largest compound page (2^10).
const MAX_SUB_PAGES: usize = 1024;

// -------------------------------------------------------------------
// CompoundPageDtor
// -------------------------------------------------------------------

/// Destructor type for compound pages.
///
/// Determines how the compound page is freed when its reference
/// count drops to zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompoundPageDtor {
    /// No special destructor — default free back to buddy.
    #[default]
    NullCompoundDtor,
    /// Standard compound page destructor.
    CompoundPageDtor,
    /// HugeTLB compound page destructor.
    HugetlbPageDtor,
    /// Transparent huge page destructor.
    TranshugePageDtor,
}

impl CompoundPageDtor {
    /// Return the numeric ID for this destructor type.
    pub const fn id(self) -> u8 {
        match self {
            Self::NullCompoundDtor => 0,
            Self::CompoundPageDtor => 1,
            Self::HugetlbPageDtor => 2,
            Self::TranshugePageDtor => 3,
        }
    }

    /// Create a destructor from its numeric ID.
    pub const fn from_id(id: u8) -> Result<Self> {
        match id {
            0 => Ok(Self::NullCompoundDtor),
            1 => Ok(Self::CompoundPageDtor),
            2 => Ok(Self::HugetlbPageDtor),
            3 => Ok(Self::TranshugePageDtor),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// -------------------------------------------------------------------
// CompoundPageFlags
// -------------------------------------------------------------------

/// Flags for compound page state.
pub struct CompoundPageFlags;

impl CompoundPageFlags {
    /// Page is the head of a compound page.
    pub const HEAD: u32 = 1 << 0;
    /// Page is a tail page.
    pub const TAIL: u32 = 1 << 1;
    /// Compound page is mapped into address space.
    pub const MAPPED: u32 = 1 << 2;
    /// Compound page is on the LRU list.
    pub const LRU: u32 = 1 << 3;
    /// Compound page is locked.
    pub const LOCKED: u32 = 1 << 4;
    /// Compound page has been split.
    pub const SPLIT: u32 = 1 << 5;
}

// -------------------------------------------------------------------
// TailPage
// -------------------------------------------------------------------

/// A tail page descriptor pointing back to its head.
#[derive(Debug, Clone, Copy)]
pub struct TailPage {
    /// PFN of this tail page.
    pub pfn: u64,
    /// Index within the compound page (1..nr_pages-1).
    pub index: u16,
    /// PFN of the head page.
    pub head_pfn: u64,
}

impl TailPage {
    /// Create a new tail page.
    pub const fn new(pfn: u64, index: u16, head_pfn: u64) -> Self {
        Self {
            pfn,
            index,
            head_pfn,
        }
    }

    /// Return the physical address of this tail page.
    pub const fn phys_addr(&self) -> u64 {
        self.pfn * PAGE_SIZE
    }
}

// -------------------------------------------------------------------
// CompoundPage
// -------------------------------------------------------------------

/// Descriptor for a compound page group.
///
/// A compound page consists of 2^order contiguous pages. The first
/// page is the head and stores all metadata; tail pages simply
/// reference the head.
#[derive(Clone)]
pub struct CompoundPage {
    /// PFN of the head page.
    head_pfn: u64,
    /// Order of the compound page (number of pages = 2^order).
    order: u8,
    /// Destructor type.
    dtor: CompoundPageDtor,
    /// Reference count (atomic in real kernel, plain here).
    refcount: u32,
    /// Map count — number of page table entries mapping this page.
    mapcount: i32,
    /// Flags.
    flags: u32,
    /// Whether this entry is in use.
    active: bool,
    /// Number of tail pages that are individually pinned.
    pinned_tails: u32,
}

impl CompoundPage {
    /// Create an inactive/empty compound page descriptor.
    const fn empty() -> Self {
        Self {
            head_pfn: 0,
            order: 0,
            dtor: CompoundPageDtor::NullCompoundDtor,
            refcount: 0,
            mapcount: 0,
            flags: 0,
            active: false,
            pinned_tails: 0,
        }
    }

    /// Return the head PFN.
    pub const fn head_pfn(&self) -> u64 {
        self.head_pfn
    }

    /// Return the physical address of the head page.
    pub const fn phys_addr(&self) -> u64 {
        self.head_pfn * PAGE_SIZE
    }

    /// Return the order of this compound page.
    pub const fn order(&self) -> u8 {
        self.order
    }

    /// Return the number of pages in this compound page (2^order).
    pub const fn nr_pages(&self) -> usize {
        1 << (self.order as usize)
    }

    /// Return the total size in bytes.
    pub const fn size_bytes(&self) -> u64 {
        (self.nr_pages() as u64) * PAGE_SIZE
    }

    /// Return the destructor type.
    pub const fn dtor(&self) -> CompoundPageDtor {
        self.dtor
    }

    /// Return the current reference count.
    pub const fn refcount(&self) -> u32 {
        self.refcount
    }

    /// Return the map count.
    pub const fn mapcount(&self) -> i32 {
        self.mapcount
    }

    /// Return the flags.
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Whether this compound page is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Whether this compound page is mapped.
    pub const fn is_mapped(&self) -> bool {
        self.flags & CompoundPageFlags::MAPPED != 0
    }

    /// Whether this compound page has been split.
    pub const fn is_split(&self) -> bool {
        self.flags & CompoundPageFlags::SPLIT != 0
    }

    /// Return the number of pinned tail pages.
    pub const fn pinned_tails(&self) -> u32 {
        self.pinned_tails
    }
}

// -------------------------------------------------------------------
// CompoundPageStats
// -------------------------------------------------------------------

/// Statistics about compound page usage.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompoundPageStats {
    /// Total compound pages allocated.
    pub total_allocated: u64,
    /// Currently active compound pages.
    pub active_count: u32,
    /// Total compound pages freed.
    pub total_freed: u64,
    /// Total compound pages split.
    pub total_split: u64,
    /// Per-order allocation counts.
    pub per_order_count: [u32; MAX_COMPOUND_ORDER as usize],
    /// Total get (reference increment) operations.
    pub total_gets: u64,
    /// Total put (reference decrement) operations.
    pub total_puts: u64,
}

// -------------------------------------------------------------------
// CompoundPageManager
// -------------------------------------------------------------------

/// Manager for compound page allocation and tracking.
///
/// Tracks up to [`MAX_COMPOUND_PAGES`] compound page descriptors
/// and provides prep, destroy, split, and reference-counting
/// operations.
pub struct CompoundPageManager {
    /// Compound page descriptor table.
    pages: [CompoundPage; MAX_COMPOUND_PAGES],
    /// Statistics.
    stats: CompoundPageStats,
    /// Next allocation ID.
    next_id: u32,
}

impl CompoundPageManager {
    /// Create a new compound page manager.
    pub const fn new() -> Self {
        Self {
            pages: [const { CompoundPage::empty() }; MAX_COMPOUND_PAGES],
            stats: CompoundPageStats {
                total_allocated: 0,
                active_count: 0,
                total_freed: 0,
                total_split: 0,
                per_order_count: [0; MAX_COMPOUND_ORDER as usize],
                total_gets: 0,
                total_puts: 0,
            },
            next_id: 0,
        }
    }

    /// Find a free slot in the page table.
    fn find_free_slot(&self) -> Result<usize> {
        for i in 0..MAX_COMPOUND_PAGES {
            if !self.pages[i].active {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find the slot for a given head PFN.
    fn find_by_pfn(&self, head_pfn: u64) -> Result<usize> {
        for i in 0..MAX_COMPOUND_PAGES {
            if self.pages[i].active && self.pages[i].head_pfn == head_pfn {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    /// Prepare (allocate) a compound page.
    ///
    /// Sets up the head page metadata, initialises tail page
    /// back-pointers (logically), and sets the destructor type.
    ///
    /// # Arguments
    /// - `head_pfn` — PFN of the first page in the contiguous block.
    /// - `order` — allocation order (must be < MAX_COMPOUND_ORDER).
    /// - `dtor` — destructor to call when freeing.
    ///
    /// # Errors
    /// - `InvalidArgument` — order too large.
    /// - `OutOfMemory` — no free descriptor slot.
    /// - `AlreadyExists` — a compound page with this PFN exists.
    pub fn prep_compound_page(
        &mut self,
        head_pfn: u64,
        order: u8,
        dtor: CompoundPageDtor,
    ) -> Result<usize> {
        if order >= MAX_COMPOUND_ORDER {
            return Err(Error::InvalidArgument);
        }
        if order == 0 {
            return Err(Error::InvalidArgument);
        }
        // Check for duplicates.
        if self.find_by_pfn(head_pfn).is_ok() {
            return Err(Error::AlreadyExists);
        }

        let slot = self.find_free_slot()?;
        self.pages[slot] = CompoundPage {
            head_pfn,
            order,
            dtor,
            refcount: 1,
            mapcount: 0,
            flags: CompoundPageFlags::HEAD,
            active: true,
            pinned_tails: 0,
        };

        self.stats.total_allocated += 1;
        self.stats.active_count += 1;
        if (order as usize) < MAX_COMPOUND_ORDER as usize {
            self.stats.per_order_count[order as usize] += 1;
        }
        self.next_id += 1;

        Ok(slot)
    }

    /// Destroy a compound page, returning it to the free pool.
    ///
    /// The destructor type is checked but not actually invoked
    /// (that is left to the frame allocator layer).
    ///
    /// # Errors
    /// - `NotFound` — no compound page with this PFN.
    /// - `Busy` — reference count is > 0.
    pub fn destroy_compound_page(&mut self, head_pfn: u64) -> Result<CompoundPageDtor> {
        let slot = self.find_by_pfn(head_pfn)?;
        if self.pages[slot].refcount > 0 {
            return Err(Error::Busy);
        }
        let dtor = self.pages[slot].dtor;
        let order = self.pages[slot].order;

        self.pages[slot] = CompoundPage::empty();
        self.stats.total_freed += 1;
        self.stats.active_count = self.stats.active_count.saturating_sub(1);
        if (order as usize) < MAX_COMPOUND_ORDER as usize {
            self.stats.per_order_count[order as usize] =
                self.stats.per_order_count[order as usize].saturating_sub(1);
        }

        Ok(dtor)
    }

    /// Split a compound page into individual order-0 pages.
    ///
    /// After splitting, the compound descriptor is marked as split
    /// and freed. Each sub-page becomes an independent page.
    ///
    /// Returns the number of individual pages produced.
    ///
    /// # Errors
    /// - `NotFound` — no compound page with this PFN.
    /// - `Busy` — page is still mapped or has refcount > 1.
    pub fn split_compound_page(&mut self, head_pfn: u64) -> Result<usize> {
        let slot = self.find_by_pfn(head_pfn)?;
        if self.pages[slot].refcount > 1 {
            return Err(Error::Busy);
        }
        if self.pages[slot].mapcount > 0 {
            return Err(Error::Busy);
        }

        let nr_pages = self.pages[slot].nr_pages();
        let order = self.pages[slot].order;

        // Mark as split and deactivate.
        self.pages[slot].flags |= CompoundPageFlags::SPLIT;
        self.pages[slot].active = false;
        self.pages[slot].refcount = 0;

        self.stats.total_split += 1;
        self.stats.active_count = self.stats.active_count.saturating_sub(1);
        if (order as usize) < MAX_COMPOUND_ORDER as usize {
            self.stats.per_order_count[order as usize] =
                self.stats.per_order_count[order as usize].saturating_sub(1);
        }

        Ok(nr_pages)
    }

    /// Get (increment reference count) a compound page.
    ///
    /// # Errors
    /// - `NotFound` — no compound page with this PFN.
    pub fn get_page(&mut self, head_pfn: u64) -> Result<u32> {
        let slot = self.find_by_pfn(head_pfn)?;
        self.pages[slot].refcount += 1;
        self.stats.total_gets += 1;
        Ok(self.pages[slot].refcount)
    }

    /// Put (decrement reference count) a compound page.
    ///
    /// Returns the new reference count. If the count reaches zero,
    /// the page should be freed by the caller.
    ///
    /// # Errors
    /// - `NotFound` — no compound page with this PFN.
    /// - `InvalidArgument` — refcount already zero.
    pub fn put_page(&mut self, head_pfn: u64) -> Result<u32> {
        let slot = self.find_by_pfn(head_pfn)?;
        if self.pages[slot].refcount == 0 {
            return Err(Error::InvalidArgument);
        }
        self.pages[slot].refcount -= 1;
        self.stats.total_puts += 1;
        Ok(self.pages[slot].refcount)
    }

    /// Increment the map count (page table entry added).
    ///
    /// # Errors
    /// - `NotFound` — no compound page with this PFN.
    pub fn map_compound_page(&mut self, head_pfn: u64) -> Result<i32> {
        let slot = self.find_by_pfn(head_pfn)?;
        self.pages[slot].mapcount += 1;
        if self.pages[slot].mapcount == 1 {
            self.pages[slot].flags |= CompoundPageFlags::MAPPED;
        }
        Ok(self.pages[slot].mapcount)
    }

    /// Decrement the map count (page table entry removed).
    ///
    /// # Errors
    /// - `NotFound` — no compound page with this PFN.
    /// - `InvalidArgument` — map count already zero.
    pub fn unmap_compound_page(&mut self, head_pfn: u64) -> Result<i32> {
        let slot = self.find_by_pfn(head_pfn)?;
        if self.pages[slot].mapcount <= 0 {
            return Err(Error::InvalidArgument);
        }
        self.pages[slot].mapcount -= 1;
        if self.pages[slot].mapcount == 0 {
            self.pages[slot].flags &= !CompoundPageFlags::MAPPED;
        }
        Ok(self.pages[slot].mapcount)
    }

    /// Return the compound head PFN for a given PFN.
    ///
    /// If `pfn` is the head of a compound page, returns itself.
    /// If `pfn` falls within the range of a known compound page,
    /// returns the head PFN.
    ///
    /// # Errors
    /// - `NotFound` — PFN does not belong to any compound page.
    pub fn compound_head(&self, pfn: u64) -> Result<u64> {
        for i in 0..MAX_COMPOUND_PAGES {
            if !self.pages[i].active {
                continue;
            }
            let head = self.pages[i].head_pfn;
            let nr = self.pages[i].nr_pages() as u64;
            if pfn >= head && pfn < head + nr {
                return Ok(head);
            }
        }
        Err(Error::NotFound)
    }

    /// Return the order of the compound page containing `pfn`.
    ///
    /// # Errors
    /// - `NotFound` — PFN does not belong to any compound page.
    pub fn compound_order(&self, pfn: u64) -> Result<u8> {
        let head = self.compound_head(pfn)?;
        let slot = self.find_by_pfn(head)?;
        Ok(self.pages[slot].order)
    }

    /// Return the number of pages in the compound page containing `pfn`.
    ///
    /// # Errors
    /// - `NotFound` — PFN does not belong to any compound page.
    pub fn compound_nr_pages(&self, pfn: u64) -> Result<usize> {
        let head = self.compound_head(pfn)?;
        let slot = self.find_by_pfn(head)?;
        Ok(self.pages[slot].nr_pages())
    }

    /// Set the destructor for a compound page.
    ///
    /// # Errors
    /// - `NotFound` — no compound page with this PFN.
    pub fn set_dtor(&mut self, head_pfn: u64, dtor: CompoundPageDtor) -> Result<()> {
        let slot = self.find_by_pfn(head_pfn)?;
        self.pages[slot].dtor = dtor;
        Ok(())
    }

    /// Pin a tail page (increment the pinned tails counter).
    ///
    /// # Errors
    /// - `NotFound` — no compound page with this PFN.
    pub fn pin_tail(&mut self, head_pfn: u64) -> Result<u32> {
        let slot = self.find_by_pfn(head_pfn)?;
        self.pages[slot].pinned_tails += 1;
        Ok(self.pages[slot].pinned_tails)
    }

    /// Unpin a tail page (decrement the pinned tails counter).
    ///
    /// # Errors
    /// - `NotFound` — no compound page with this PFN.
    /// - `InvalidArgument` — no tails are pinned.
    pub fn unpin_tail(&mut self, head_pfn: u64) -> Result<u32> {
        let slot = self.find_by_pfn(head_pfn)?;
        if self.pages[slot].pinned_tails == 0 {
            return Err(Error::InvalidArgument);
        }
        self.pages[slot].pinned_tails -= 1;
        Ok(self.pages[slot].pinned_tails)
    }

    /// Generate the tail page descriptors for a compound page.
    ///
    /// Returns the number of tails written into `out`.
    ///
    /// # Errors
    /// - `NotFound` — no compound page with this PFN.
    /// - `InvalidArgument` — output buffer too small.
    pub fn get_tail_pages(&self, head_pfn: u64, out: &mut [TailPage]) -> Result<usize> {
        let slot = self.find_by_pfn(head_pfn)?;
        let nr_pages = self.pages[slot].nr_pages();
        let nr_tails = nr_pages - 1;
        if out.len() < nr_tails {
            return Err(Error::InvalidArgument);
        }
        for i in 0..nr_tails {
            out[i] = TailPage::new(head_pfn + (i as u64) + 1, (i + 1) as u16, head_pfn);
        }
        Ok(nr_tails)
    }

    /// Return a reference to a compound page descriptor by head PFN.
    ///
    /// # Errors
    /// - `NotFound` — no compound page with this PFN.
    pub fn get_compound_page(&self, head_pfn: u64) -> Result<&CompoundPage> {
        let slot = self.find_by_pfn(head_pfn)?;
        Ok(&self.pages[slot])
    }

    /// Return current statistics.
    pub const fn stats(&self) -> &CompoundPageStats {
        &self.stats
    }

    /// Return the number of active compound pages.
    pub const fn active_count(&self) -> u32 {
        self.stats.active_count
    }
}
