// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SLOB allocator — Simple List Of Blocks.
//!
//! SLOB is a compact, space-efficient allocator targeting small embedded
//! or memory-constrained systems. It maintains three size-segregated
//! free-lists (small, medium, large) and uses a first-fit strategy within
//! each list.
//!
//! Unlike SLAB or SLUB, SLOB does not maintain per-CPU caches or complex
//! object metadata. Every allocation is preceded by a small inline header
//! that records the block size, enabling `O(1)` free operations.
//!
//! # Design
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │  SLOB page  (PAGE_SIZE bytes)               │
//! ├──────┬──────┬──────┬──────────────┬─────────┤
//! │ hdr0 │ obj0 │ hdr1 │    free      │ padding │
//! └──────┴──────┴──────┴──────────────┴─────────┘
//! ```
//!
//! The free portion of each page is tracked as a singly-linked list of
//! [`SlobFreeBlock`] entries embedded directly in the free memory.
//!
//! # Segregated free-lists
//!
//! | List   | Object size range         |
//! |--------|---------------------------|
//! | Small  | 1 – SLOB_SMALL_MAX bytes  |
//! | Medium | SLOB_SMALL_MAX+1 – 256 B  |
//! | Large  | 257 B – PAGE_SIZE−header  |
//!
//! # Key types
//!
//! - [`SlobBlock`] — inline allocation header
//! - [`SlobPage`] — a single SLOB page with its free-list
//! - [`SlobAllocator`] — top-level allocator owning the page pool
//! - [`SlobStats`] — allocation and fragmentation statistics

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size managed by SLOB.
pub const SLOB_PAGE_SIZE: usize = 4096;

/// Upper bound (inclusive) for the small free-list.
pub const SLOB_SMALL_MAX: usize = 64;

/// Upper bound (inclusive) for the medium free-list.
pub const SLOB_MEDIUM_MAX: usize = 256;

/// Size of the inline allocation header in bytes.
pub const SLOB_HEADER_SIZE: usize = core::mem::size_of::<SlobBlock>();

/// Maximum usable bytes per SLOB page.
pub const SLOB_MAX_OBJECT: usize = SLOB_PAGE_SIZE - SLOB_HEADER_SIZE;

/// Maximum number of SLOB pages the allocator manages.
pub const SLOB_MAX_PAGES: usize = 512;

/// Poison value written to freed blocks in debug builds.
pub const SLOB_FREE_POISON: u8 = 0xFD;

// -------------------------------------------------------------------
// SlobSizeClass
// -------------------------------------------------------------------

/// Which free-list an object belongs to based on its size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlobSizeClass {
    /// 1–SLOB_SMALL_MAX bytes.
    Small,
    /// SLOB_SMALL_MAX+1–SLOB_MEDIUM_MAX bytes.
    Medium,
    /// SLOB_MEDIUM_MAX+1–SLOB_MAX_OBJECT bytes.
    Large,
}

impl SlobSizeClass {
    /// Classify `size` into the appropriate free-list.
    pub fn for_size(size: usize) -> Option<Self> {
        if size == 0 || size > SLOB_MAX_OBJECT {
            return None;
        }
        if size <= SLOB_SMALL_MAX {
            Some(Self::Small)
        } else if size <= SLOB_MEDIUM_MAX {
            Some(Self::Medium)
        } else {
            Some(Self::Large)
        }
    }
}

// -------------------------------------------------------------------
// SlobBlock (inline header)
// -------------------------------------------------------------------

/// Inline allocation header stored immediately before every SLOB object.
///
/// When the block is free, `units` encodes the number of usable bytes
/// following the header, and `next_offset` is the byte offset (from the
/// start of the page) to the next free block, or `0` if this is the last.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SlobBlock {
    /// For allocated blocks: requested size in bytes.
    /// For free blocks: free region size in bytes.
    pub units: u32,
    /// For free blocks: byte offset to the next free block (0 = end).
    pub next_offset: u32,
}

impl SlobBlock {
    /// Create a free-list header for a region of `units` bytes.
    pub const fn free(units: u32, next_offset: u32) -> Self {
        Self { units, next_offset }
    }

    /// Create an allocation header for `units` usable bytes.
    pub const fn alloc(units: u32) -> Self {
        Self {
            units,
            next_offset: 0,
        }
    }
}

// -------------------------------------------------------------------
// SlobPage
// -------------------------------------------------------------------

/// A single SLOB-managed page.
///
/// The `data` array represents the raw page contents. The free-list is
/// embedded as a chain of [`SlobBlock`] headers within the free regions.
#[derive(Debug)]
pub struct SlobPage {
    /// Raw page contents.
    data: [u8; SLOB_PAGE_SIZE],
    /// Number of free bytes remaining on this page.
    free_bytes: usize,
    /// Offset of the first free block within `data`.
    free_list_head: usize,
    /// Total bytes allocated from this page (not counting headers).
    allocated_bytes: usize,
    /// Page index within the allocator's pool.
    index: u32,
    /// Which size class this page primarily serves.
    size_class: SlobSizeClass,
}

impl SlobPage {
    /// Initialize a new SLOB page for the given size class.
    pub fn new(index: u32, size_class: SlobSizeClass) -> Self {
        let mut page = Self {
            data: [0u8; SLOB_PAGE_SIZE],
            free_bytes: SLOB_PAGE_SIZE - SLOB_HEADER_SIZE,
            free_list_head: 0,
            allocated_bytes: 0,
            index,
            size_class,
        };
        // Place the initial free block at offset 0.
        let initial = SlobBlock::free((SLOB_PAGE_SIZE - SLOB_HEADER_SIZE) as u32, 0);
        page.write_block(0, initial);
        page
    }

    /// Return the number of free bytes on this page.
    pub fn free_bytes(&self) -> usize {
        self.free_bytes
    }

    /// Return the page index.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Return the size class this page serves.
    pub fn size_class(&self) -> SlobSizeClass {
        self.size_class
    }

    /// Attempt to allocate `size` bytes from this page.
    ///
    /// Returns the byte offset within `data` where the usable object starts,
    /// or an error if no suitable free block exists.
    pub fn alloc(&mut self, size: usize) -> Result<usize> {
        if size == 0 || size > SLOB_MAX_OBJECT {
            return Err(Error::InvalidArgument);
        }
        let needed = size + SLOB_HEADER_SIZE;
        if self.free_bytes < size {
            return Err(Error::OutOfMemory);
        }

        let mut prev_offset: Option<usize> = None;
        let mut cur_offset = self.free_list_head;

        loop {
            let block = self.read_block(cur_offset);
            let block_usable = block.units as usize;
            if block_usable >= size {
                // First-fit found.
                let data_offset = cur_offset + SLOB_HEADER_SIZE;
                let remaining = block_usable.saturating_sub(size);

                if remaining >= SLOB_HEADER_SIZE + 1 {
                    // Split the block: write a new free block for the remainder.
                    let new_free_offset = data_offset + size;
                    let new_next = block.next_offset;
                    self.write_block(
                        new_free_offset - SLOB_HEADER_SIZE,
                        SlobBlock::free((remaining - SLOB_HEADER_SIZE) as u32, new_next),
                    );
                    // Link predecessor to the new free block.
                    let new_free_hdr_offset = new_free_offset - SLOB_HEADER_SIZE;
                    match prev_offset {
                        Some(p) => {
                            let mut prev = self.read_block(p);
                            prev.next_offset = new_free_hdr_offset as u32;
                            self.write_block(p, prev);
                        }
                        None => {
                            self.free_list_head = new_free_hdr_offset;
                        }
                    }
                } else {
                    // Consume the entire block (no leftover).
                    match prev_offset {
                        Some(p) => {
                            let mut prev = self.read_block(p);
                            prev.next_offset = block.next_offset;
                            self.write_block(p, prev);
                        }
                        None => {
                            self.free_list_head = if block.next_offset == 0 {
                                0
                            } else {
                                block.next_offset as usize
                            };
                        }
                    }
                }

                // Write the allocation header.
                self.write_block(cur_offset, SlobBlock::alloc(size as u32));
                self.free_bytes = self.free_bytes.saturating_sub(needed);
                self.allocated_bytes += size;
                return Ok(data_offset);
            }

            if block.next_offset == 0 {
                break;
            }
            prev_offset = Some(cur_offset);
            cur_offset = block.next_offset as usize;
        }
        Err(Error::OutOfMemory)
    }

    /// Free the object at byte offset `data_offset` within `data`.
    pub fn free(&mut self, data_offset: usize) -> Result<()> {
        if data_offset < SLOB_HEADER_SIZE || data_offset >= SLOB_PAGE_SIZE {
            return Err(Error::InvalidArgument);
        }
        let hdr_offset = data_offset - SLOB_HEADER_SIZE;
        let block = self.read_block(hdr_offset);
        let size = block.units as usize;

        // Insert this block at the head of the free list.
        let old_head = self.free_list_head as u32;
        self.write_block(hdr_offset, SlobBlock::free(size as u32, old_head));
        self.free_list_head = hdr_offset;
        self.free_bytes += size + SLOB_HEADER_SIZE;
        self.allocated_bytes = self.allocated_bytes.saturating_sub(size);
        Ok(())
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    /// Read a [`SlobBlock`] from `data` at byte offset `offset`.
    fn read_block(&self, offset: usize) -> SlobBlock {
        // SAFETY: offset is always within bounds as ensured by the allocator logic.
        let bytes = &self.data[offset..offset + SLOB_HEADER_SIZE];
        let units = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let next = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        SlobBlock {
            units,
            next_offset: next,
        }
    }

    /// Write a [`SlobBlock`] into `data` at byte offset `offset`.
    fn write_block(&mut self, offset: usize, block: SlobBlock) {
        let bytes = &mut self.data[offset..offset + SLOB_HEADER_SIZE];
        bytes[..4].copy_from_slice(&block.units.to_le_bytes());
        bytes[4..8].copy_from_slice(&block.next_offset.to_le_bytes());
    }
}

// -------------------------------------------------------------------
// SlobStats
// -------------------------------------------------------------------

/// Aggregate statistics for the SLOB allocator.
#[derive(Debug, Clone, Copy, Default)]
pub struct SlobStats {
    /// Total allocation requests (by size class).
    pub small_allocs: u64,
    /// Total medium-class allocations.
    pub medium_allocs: u64,
    /// Total large-class allocations.
    pub large_allocs: u64,
    /// Total free operations.
    pub frees: u64,
    /// Number of SLOB pages currently in use.
    pub pages_in_use: u32,
    /// Total bytes currently allocated (excluding headers).
    pub allocated_bytes: u64,
}

// -------------------------------------------------------------------
// SlobAllocator
// -------------------------------------------------------------------

/// Top-level SLOB allocator.
///
/// Owns a fixed pool of [`SlobPage`] entries and routes allocation
/// requests to the appropriate size-class page.
#[derive(Debug)]
pub struct SlobAllocator {
    /// Page pool (Some if the page is in use).
    pages: [Option<SlobPage>; SLOB_MAX_PAGES],
    /// Number of pages currently allocated.
    page_count: usize,
    /// Aggregate statistics.
    stats: SlobStats,
}

impl SlobAllocator {
    /// Create a new empty SLOB allocator.
    pub const fn new() -> Self {
        Self {
            pages: [const { None }; SLOB_MAX_PAGES],
            page_count: 0,
            stats: SlobStats {
                small_allocs: 0,
                medium_allocs: 0,
                large_allocs: 0,
                frees: 0,
                pages_in_use: 0,
                allocated_bytes: 0,
            },
        }
    }

    /// Allocate `size` bytes.
    ///
    /// Returns the page index and data offset within that page, or an error.
    pub fn alloc(&mut self, size: usize) -> Result<(u32, usize)> {
        let class = SlobSizeClass::for_size(size).ok_or(Error::InvalidArgument)?;

        // Try existing pages of the matching class first.
        for i in 0..SLOB_MAX_PAGES {
            if let Some(slot) = &mut self.pages[i] {
                if slot.size_class() == class && slot.free_bytes() >= size + SLOB_HEADER_SIZE {
                    if let Ok(offset) = slot.alloc(size) {
                        let idx = slot.index();
                        self.update_stats_alloc(class, size);
                        return Ok((idx, offset));
                    }
                }
            }
        }

        // Allocate a new page.
        let page_idx = self.alloc_page(class)?;
        let slot = self.pages[page_idx as usize]
            .as_mut()
            .ok_or(Error::OutOfMemory)?;
        let offset = slot.alloc(size)?;
        self.update_stats_alloc(class, size);
        Ok((page_idx, offset))
    }

    /// Free an object identified by `(page_index, data_offset)`.
    pub fn free(&mut self, page_index: u32, data_offset: usize) -> Result<()> {
        let slot = self
            .pages
            .get_mut(page_index as usize)
            .ok_or(Error::InvalidArgument)?;
        let page = slot.as_mut().ok_or(Error::NotFound)?;
        page.free(data_offset)?;
        self.stats.frees += 1;
        self.stats.allocated_bytes = self
            .stats
            .allocated_bytes
            .saturating_sub(data_offset as u64);
        Ok(())
    }

    /// Return a snapshot of allocator statistics.
    pub fn stats(&self) -> &SlobStats {
        &self.stats
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    /// Allocate a new page slot for the given size class.
    fn alloc_page(&mut self, class: SlobSizeClass) -> Result<u32> {
        for (i, slot) in self.pages.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(SlobPage::new(i as u32, class));
                self.page_count += 1;
                self.stats.pages_in_use += 1;
                return Ok(i as u32);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Update allocation statistics.
    fn update_stats_alloc(&mut self, class: SlobSizeClass, size: usize) {
        match class {
            SlobSizeClass::Small => self.stats.small_allocs += 1,
            SlobSizeClass::Medium => self.stats.medium_allocs += 1,
            SlobSizeClass::Large => self.stats.large_allocs += 1,
        }
        self.stats.allocated_bytes += size as u64;
    }
}

impl Default for SlobAllocator {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_class() {
        assert_eq!(SlobSizeClass::for_size(1), Some(SlobSizeClass::Small));
        assert_eq!(SlobSizeClass::for_size(64), Some(SlobSizeClass::Small));
        assert_eq!(SlobSizeClass::for_size(65), Some(SlobSizeClass::Medium));
        assert_eq!(SlobSizeClass::for_size(256), Some(SlobSizeClass::Medium));
        assert_eq!(SlobSizeClass::for_size(257), Some(SlobSizeClass::Large));
        assert_eq!(SlobSizeClass::for_size(0), None);
    }

    #[test]
    fn test_page_alloc_and_free() {
        let mut page = SlobPage::new(0, SlobSizeClass::Small);
        let off = page.alloc(32).unwrap();
        assert!(off >= SLOB_HEADER_SIZE);
        page.free(off).unwrap();
    }

    #[test]
    fn test_allocator_small() {
        let mut alloc = SlobAllocator::new();
        let (page, offset) = alloc.alloc(16).unwrap();
        assert_eq!(alloc.stats().small_allocs, 1);
        alloc.free(page, offset).unwrap();
        assert_eq!(alloc.stats().frees, 1);
    }
}
