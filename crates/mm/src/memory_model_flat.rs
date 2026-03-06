// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Flat memory model: direct PFN-to-page translation.
//!
//! In the flat memory model, physical memory is assumed to be
//! contiguous from a base PFN. The `mem_map` array holds a
//! `PageDescriptor` for every PFN in the range `[ARCH_PFN_OFFSET,
//! ARCH_PFN_OFFSET + max_pfn)`. PFN-to-page lookups are a simple
//! array index: `mem_map[pfn - ARCH_PFN_OFFSET]`.
//!
//! This model is simple and fast but wastes memory for systems with
//! physical address holes, because every PFN in the range must have
//! a descriptor even if the corresponding frame is absent.
//!
//! # Key Types
//!
//! - [`PageFlags`] — per-page state flags
//! - [`PageDescriptor`] — struct-page equivalent metadata
//! - [`PfnRange`] — a validated PFN range
//! - [`MemMapArray`] — the global mem_map array
//! - [`FlatMemoryModel`] — top-level manager
//! - [`FlatMemStats`] — statistics
//!
//! Reference: Linux `include/asm-generic/memory_model.h`,
//! `mm/page_alloc.c`, `arch/x86/include/asm/page.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Default architecture PFN offset (typically 0 on x86_64).
const DEFAULT_ARCH_PFN_OFFSET: u64 = 0;

/// Maximum number of pages in the mem_map array.
const MAX_MEM_MAP_PAGES: usize = 4096;

/// Maximum number of PFN ranges for section-based validation.
const MAX_PFN_RANGES: usize = 32;

/// Number of pages per section (128 MiB section = 32768 pages).
const PAGES_PER_SECTION: u64 = 32768;

/// Invalid NUMA node.
const NUMA_NO_NODE: u8 = 0xFF;

// -------------------------------------------------------------------
// PageFlags
// -------------------------------------------------------------------

/// Per-page state flags stored in each `PageDescriptor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PageFlags(u32);

impl PageFlags {
    /// Page frame is present in physical memory.
    pub const PRESENT: Self = Self(1 << 0);
    /// Page is reserved (kernel, BIOS, etc).
    pub const RESERVED: Self = Self(1 << 1);
    /// Page is allocated to a user.
    pub const ALLOCATED: Self = Self(1 << 2);
    /// Page is on an LRU list.
    pub const LRU: Self = Self(1 << 3);
    /// Page is part of slab allocation.
    pub const SLAB: Self = Self(1 << 4);
    /// Page is a compound head page.
    pub const COMPOUND_HEAD: Self = Self(1 << 5);
    /// Page is a compound tail page.
    pub const COMPOUND_TAIL: Self = Self(1 << 6);
    /// Page has been written to (dirty).
    pub const DIRTY: Self = Self(1 << 7);
    /// Page is locked for I/O.
    pub const LOCKED: Self = Self(1 << 8);

    /// Returns true if the given flag is set.
    pub fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Sets a flag.
    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    /// Clears a flag.
    pub fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }

    /// Returns the raw flag value.
    pub fn bits(self) -> u32 {
        self.0
    }
}

// -------------------------------------------------------------------
// PageDescriptor
// -------------------------------------------------------------------

/// Per-page metadata — the flat-model equivalent of `struct page`.
#[derive(Debug, Clone, Copy)]
pub struct PageDescriptor {
    /// Page frame number.
    pub pfn: u64,
    /// State flags.
    pub flags: PageFlags,
    /// Reference count.
    pub refcount: u32,
    /// Map count (number of page table mappings).
    pub mapcount: i32,
    /// NUMA node this page belongs to.
    pub node_id: u8,
    /// Allocation order (0 for base pages).
    pub order: u8,
}

impl Default for PageDescriptor {
    fn default() -> Self {
        Self {
            pfn: 0,
            flags: PageFlags::default(),
            refcount: 0,
            mapcount: 0,
            node_id: NUMA_NO_NODE,
            order: 0,
        }
    }
}

impl PageDescriptor {
    /// Returns the physical address of this page.
    pub fn phys_addr(&self) -> u64 {
        self.pfn * PAGE_SIZE
    }

    /// Returns true if the page is present in physical memory.
    pub fn is_present(&self) -> bool {
        self.flags.contains(PageFlags::PRESENT)
    }

    /// Returns true if the page is currently allocated.
    pub fn is_allocated(&self) -> bool {
        self.flags.contains(PageFlags::ALLOCATED)
    }

    /// Increments the reference count.
    pub fn get_ref(&mut self) {
        self.refcount = self.refcount.saturating_add(1);
    }

    /// Decrements the reference count. Returns true if it hit zero.
    pub fn put_ref(&mut self) -> bool {
        self.refcount = self.refcount.saturating_sub(1);
        self.refcount == 0
    }
}

// -------------------------------------------------------------------
// PfnRange
// -------------------------------------------------------------------

/// A validated PFN range within the flat memory model.
#[derive(Debug, Clone, Copy, Default)]
pub struct PfnRange {
    /// First PFN in the range.
    pub start_pfn: u64,
    /// Number of PFNs in the range.
    pub nr_pfns: u64,
    /// NUMA node this range belongs to.
    pub node_id: u8,
    /// Whether this range is online and usable.
    pub online: bool,
}

impl PfnRange {
    /// Returns the end PFN (exclusive).
    pub fn end_pfn(&self) -> u64 {
        self.start_pfn + self.nr_pfns
    }

    /// Returns true if `pfn` falls within this range.
    pub fn contains_pfn(&self, pfn: u64) -> bool {
        pfn >= self.start_pfn && pfn < self.end_pfn()
    }

    /// Returns the section number for the start of this range.
    pub fn start_section(&self) -> u64 {
        self.start_pfn / PAGES_PER_SECTION
    }
}

// -------------------------------------------------------------------
// MemMapArray
// -------------------------------------------------------------------

/// The global mem_map array holding per-page descriptors.
///
/// In the flat model this is a dense array indexed by
/// `pfn - arch_pfn_offset`.
pub struct MemMapArray {
    /// Dense page descriptor storage.
    pages: [PageDescriptor; MAX_MEM_MAP_PAGES],
    /// Number of valid entries.
    nr_pages: usize,
}

impl MemMapArray {
    /// Creates a new empty mem_map array.
    pub fn new() -> Self {
        Self {
            pages: [const {
                PageDescriptor {
                    pfn: 0,
                    flags: PageFlags(0),
                    refcount: 0,
                    mapcount: 0,
                    node_id: NUMA_NO_NODE,
                    order: 0,
                }
            }; MAX_MEM_MAP_PAGES],
            nr_pages: 0,
        }
    }

    /// Returns a reference to the descriptor at index `idx`.
    pub fn get(&self, idx: usize) -> Result<&PageDescriptor> {
        if idx >= self.nr_pages {
            return Err(Error::NotFound);
        }
        Ok(&self.pages[idx])
    }

    /// Returns a mutable reference to the descriptor at `idx`.
    pub fn get_mut(&mut self, idx: usize) -> Result<&mut PageDescriptor> {
        if idx >= self.nr_pages {
            return Err(Error::NotFound);
        }
        Ok(&mut self.pages[idx])
    }

    /// Initializes `count` page descriptors starting at `base_pfn`.
    pub fn init_range(&mut self, base_pfn: u64, count: usize, node_id: u8) -> Result<()> {
        if count > MAX_MEM_MAP_PAGES {
            return Err(Error::OutOfMemory);
        }
        for i in 0..count {
            self.pages[i] = PageDescriptor {
                pfn: base_pfn + i as u64,
                flags: PageFlags::PRESENT,
                refcount: 0,
                mapcount: 0,
                node_id,
                order: 0,
            };
        }
        self.nr_pages = count;
        Ok(())
    }

    /// Returns the number of valid entries.
    pub fn len(&self) -> usize {
        self.nr_pages
    }

    /// Returns true if the array is empty.
    pub fn is_empty(&self) -> bool {
        self.nr_pages == 0
    }
}

// -------------------------------------------------------------------
// FlatMemStats
// -------------------------------------------------------------------

/// Statistics for the flat memory model.
#[derive(Debug, Clone, Copy, Default)]
pub struct FlatMemStats {
    /// Total pages in the mem_map array.
    pub total_pages: u64,
    /// Pages marked as present.
    pub present_pages: u64,
    /// Pages marked as reserved.
    pub reserved_pages: u64,
    /// Pages currently allocated.
    pub allocated_pages: u64,
    /// PFN lookup operations performed.
    pub pfn_lookups: u64,
    /// PFN lookups that were valid.
    pub pfn_valid_hits: u64,
    /// PFN lookups that were out of range.
    pub pfn_valid_misses: u64,
    /// Total PFN ranges registered.
    pub pfn_ranges: u64,
}

// -------------------------------------------------------------------
// FlatMemoryModel
// -------------------------------------------------------------------

/// Top-level flat memory model manager.
///
/// Provides direct PFN-to-page translation via the mem_map array,
/// PFN validation, section-based range management, and statistics.
pub struct FlatMemoryModel {
    /// The global mem_map array.
    mem_map: MemMapArray,
    /// Architecture PFN offset (base PFN of physical memory).
    arch_pfn_offset: u64,
    /// Maximum valid PFN.
    max_pfn: u64,
    /// Registered PFN ranges for section-based validation.
    pfn_ranges: [PfnRange; MAX_PFN_RANGES],
    /// Number of registered PFN ranges.
    nr_ranges: usize,
    /// Cumulative statistics.
    stats: FlatMemStats,
}

impl FlatMemoryModel {
    /// Creates a new flat memory model.
    ///
    /// `arch_pfn_offset` is the base PFN (typically 0 on x86_64).
    /// `max_pfn` is the highest valid PFN.
    pub fn new(arch_pfn_offset: u64, max_pfn: u64) -> Self {
        Self {
            mem_map: MemMapArray::new(),
            arch_pfn_offset,
            max_pfn,
            pfn_ranges: [const {
                PfnRange {
                    start_pfn: 0,
                    nr_pfns: 0,
                    node_id: 0,
                    online: false,
                }
            }; MAX_PFN_RANGES],
            nr_ranges: 0,
            stats: FlatMemStats::default(),
        }
    }

    /// Returns current statistics.
    pub fn stats(&self) -> &FlatMemStats {
        &self.stats
    }

    /// Returns the architecture PFN offset.
    pub fn arch_pfn_offset(&self) -> u64 {
        self.arch_pfn_offset
    }

    /// Returns the maximum PFN.
    pub fn max_pfn(&self) -> u64 {
        self.max_pfn
    }

    /// Initialises the mem_map with pages on a given NUMA node.
    pub fn init_mem_map(&mut self, nr_pages: usize, node_id: u8) -> Result<()> {
        self.mem_map
            .init_range(self.arch_pfn_offset, nr_pages, node_id)?;
        self.stats.total_pages = nr_pages as u64;
        self.stats.present_pages = nr_pages as u64;
        Ok(())
    }

    /// Converts a PFN to a mem_map array index.
    fn pfn_to_index(&self, pfn: u64) -> Result<usize> {
        if pfn < self.arch_pfn_offset || pfn > self.max_pfn {
            return Err(Error::InvalidArgument);
        }
        let idx = (pfn - self.arch_pfn_offset) as usize;
        if idx >= self.mem_map.len() {
            return Err(Error::NotFound);
        }
        Ok(idx)
    }

    /// Checks whether a PFN is valid (present in the flat range).
    pub fn pfn_valid(&mut self, pfn: u64) -> bool {
        self.stats.pfn_lookups += 1;
        if pfn < self.arch_pfn_offset || pfn > self.max_pfn {
            self.stats.pfn_valid_misses += 1;
            return false;
        }
        let idx = (pfn - self.arch_pfn_offset) as usize;
        if idx >= self.mem_map.len() {
            self.stats.pfn_valid_misses += 1;
            return false;
        }
        self.stats.pfn_valid_hits += 1;
        true
    }

    /// Translates a PFN to its `PageDescriptor` reference.
    pub fn pfn_to_page(&self, pfn: u64) -> Result<&PageDescriptor> {
        let idx = self.pfn_to_index(pfn)?;
        self.mem_map.get(idx)
    }

    /// Translates a PFN to a mutable `PageDescriptor` reference.
    pub fn pfn_to_page_mut(&mut self, pfn: u64) -> Result<&mut PageDescriptor> {
        let idx = self.pfn_to_index(pfn)?;
        self.mem_map.get_mut(idx)
    }

    /// Translates a physical address to its `PageDescriptor`.
    pub fn phys_to_page(&self, phys_addr: u64) -> Result<&PageDescriptor> {
        let pfn = phys_addr / PAGE_SIZE;
        self.pfn_to_page(pfn)
    }

    /// Converts a `PageDescriptor` PFN back to a physical address.
    pub fn page_to_phys(page: &PageDescriptor) -> u64 {
        page.pfn * PAGE_SIZE
    }

    /// Registers a PFN range for section-based validation.
    pub fn register_pfn_range(&mut self, start_pfn: u64, nr_pfns: u64, node_id: u8) -> Result<()> {
        if self.nr_ranges >= MAX_PFN_RANGES {
            return Err(Error::OutOfMemory);
        }
        self.pfn_ranges[self.nr_ranges] = PfnRange {
            start_pfn,
            nr_pfns,
            node_id,
            online: true,
        };
        self.nr_ranges += 1;
        self.stats.pfn_ranges += 1;
        Ok(())
    }

    /// Checks if a PFN falls within any registered range.
    pub fn pfn_in_registered_range(&self, pfn: u64) -> bool {
        for i in 0..self.nr_ranges {
            if self.pfn_ranges[i].contains_pfn(pfn) {
                return true;
            }
        }
        false
    }

    /// Returns the NUMA node for a given PFN, or `NUMA_NO_NODE`.
    pub fn pfn_to_nid(&self, pfn: u64) -> u8 {
        for i in 0..self.nr_ranges {
            if self.pfn_ranges[i].contains_pfn(pfn) {
                return self.pfn_ranges[i].node_id;
            }
        }
        NUMA_NO_NODE
    }

    /// Allocates a page by marking it as allocated.
    pub fn alloc_page(&mut self, pfn: u64) -> Result<()> {
        let idx = self.pfn_to_index(pfn)?;
        let page = self.mem_map.get_mut(idx)?;
        if page.flags.contains(PageFlags::ALLOCATED) {
            return Err(Error::Busy);
        }
        page.flags.insert(PageFlags::ALLOCATED);
        page.refcount = 1;
        self.stats.allocated_pages += 1;
        Ok(())
    }

    /// Frees a page by clearing the allocated flag.
    pub fn free_page(&mut self, pfn: u64) -> Result<()> {
        let idx = self.pfn_to_index(pfn)?;
        let page = self.mem_map.get_mut(idx)?;
        if !page.flags.contains(PageFlags::ALLOCATED) {
            return Err(Error::InvalidArgument);
        }
        page.flags.remove(PageFlags::ALLOCATED);
        page.refcount = 0;
        page.mapcount = 0;
        self.stats.allocated_pages = self.stats.allocated_pages.saturating_sub(1);
        Ok(())
    }

    /// Returns the number of PFN ranges registered.
    pub fn nr_ranges(&self) -> usize {
        self.nr_ranges
    }

    /// Returns the section number containing a given PFN.
    pub fn pfn_to_section(pfn: u64) -> u64 {
        pfn / PAGES_PER_SECTION
    }

    /// Validates that `pfn` belongs to an online section.
    pub fn pfn_section_valid(&self, pfn: u64) -> bool {
        for i in 0..self.nr_ranges {
            if self.pfn_ranges[i].contains_pfn(pfn) && self.pfn_ranges[i].online {
                return true;
            }
        }
        false
    }
}
