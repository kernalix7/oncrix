// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Address space dirty page tracking.
//!
//! Tracks which pages in an address_space (file mapping) are dirty and
//! need to be written back to storage.  Uses a tag-based system for
//! efficient dirty page lookup and provides a writeback iterator that
//! walks tagged pages in order.
//!
//! # Architecture
//!
//! ```text
//! struct address_space (per-inode file mapping)
//! ┌──────────────────────────────────────────────────────┐
//! │ DirtyMapping                                         │
//! │   ├── page_tags[0..MAX_PAGES]  — per-page tag bits   │
//! │   ├── dirty_count              — number of dirty     │
//! │   ├── writeback_count          — pages being written │
//! │   └── dirty_ranges[]           — coalesced ranges    │
//! │                                                      │
//! │ Tags:                                                │
//! │   DIRTY      — page has been modified                │
//! │   TOWRITE    — page selected for current writeback   │
//! │   WRITEBACK  — I/O in progress for this page         │
//! │   RECLAIM    — page tagged for reclaim               │
//! └──────────────────────────────────────────────────────┘
//! ```
//!
//! # Tag-based lookup
//!
//! Pages are tagged with [`DirtyTag`] flags.  The writeback subsystem
//! scans for pages with the `DIRTY` tag, promotes them to `TOWRITE`,
//! and finally `WRITEBACK` while I/O is in flight.
//!
//! # Writeback iteration
//!
//! [`WritebackIter`] walks the mapping's page array in ascending page
//! index order, yielding pages that match a requested tag mask.
//!
//! # Reference
//!
//! Linux `include/linux/pagemap.h`, `mm/page-writeback.c`,
//! `fs/fs-writeback.c`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of pages tracked per mapping.
const MAX_PAGES: usize = 4096;

/// Maximum number of coalesced dirty ranges.
const MAX_DIRTY_RANGES: usize = 128;

/// Maximum number of tracked mappings.
const MAX_MAPPINGS: usize = 256;

/// Page size in bytes.
const PAGE_SIZE: u64 = 4096;

// ── DirtyTag ──────────────────────────────────────────────────────────────────

/// Tag bits applied to pages in an address_space.
///
/// Multiple tags can be set simultaneously on a single page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirtyTag(u8);

impl DirtyTag {
    /// No tags set.
    pub const NONE: Self = Self(0);
    /// Page has been modified and needs writeback.
    pub const DIRTY: Self = Self(1 << 0);
    /// Page has been selected for the current writeback batch.
    pub const TOWRITE: Self = Self(1 << 1);
    /// I/O is in progress for this page.
    pub const WRITEBACK: Self = Self(1 << 2);
    /// Page is tagged for reclaim.
    pub const RECLAIM: Self = Self(1 << 3);

    /// Create a tag set from raw bits.
    pub const fn from_raw(v: u8) -> Self {
        Self(v)
    }

    /// Return the raw bits.
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Check whether a specific tag is set.
    pub const fn has(self, tag: Self) -> bool {
        (self.0 & tag.0) == tag.0
    }

    /// Set a tag.
    pub const fn set(self, tag: Self) -> Self {
        Self(self.0 | tag.0)
    }

    /// Clear a tag.
    pub const fn clear(self, tag: Self) -> Self {
        Self(self.0 & !tag.0)
    }

    /// Check whether any tag is set.
    pub const fn is_any(self) -> bool {
        self.0 != 0
    }
}

// ── DirtyState ────────────────────────────────────────────────────────────────

/// Overall dirty state of a mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirtyState {
    /// No dirty pages.
    Clean,
    /// Some pages are dirty, not yet being written.
    Dirty,
    /// Writeback is in progress for some pages.
    Writeback,
    /// Both dirty and writeback pages exist (new writes during flush).
    DirtyAndWriteback,
}

// ── DirtyRange ────────────────────────────────────────────────────────────────

/// A contiguous range of dirty pages.
///
/// Produced by coalescing adjacent dirty page indices for efficient
/// writeback scheduling.
#[derive(Debug, Clone, Copy)]
pub struct DirtyRange {
    /// Starting page index.
    pub start: u64,
    /// Number of contiguous dirty pages.
    pub count: u32,
    /// Whether this range has been selected for writeback.
    pub scheduled: bool,
}

impl DirtyRange {
    /// Create a new dirty range.
    pub const fn new(start: u64, count: u32) -> Self {
        Self {
            start,
            count,
            scheduled: false,
        }
    }

    /// Return the byte offset of the start of this range.
    pub const fn start_offset(&self) -> u64 {
        self.start * PAGE_SIZE
    }

    /// Return the total byte length of this range.
    pub const fn byte_length(&self) -> u64 {
        self.count as u64 * PAGE_SIZE
    }

    /// Return the page index one past the end.
    pub const fn end_page(&self) -> u64 {
        self.start + self.count as u64
    }

    /// Check whether a page index falls within this range.
    pub const fn contains_page(&self, page: u64) -> bool {
        page >= self.start && page < self.start + self.count as u64
    }
}

// ── Per-page tag storage ──────────────────────────────────────────────────────

/// Compact tag storage for a fixed array of pages.
struct PageTags {
    /// Tag bits for each page index.
    tags: [u8; MAX_PAGES],
    /// Number of pages with the DIRTY tag.
    dirty_count: u32,
    /// Number of pages with the WRITEBACK tag.
    writeback_count: u32,
}

impl PageTags {
    const fn new() -> Self {
        Self {
            tags: [0u8; MAX_PAGES],
            dirty_count: 0,
            writeback_count: 0,
        }
    }

    /// Get the tag set for a page.
    fn get(&self, page: usize) -> DirtyTag {
        if page >= MAX_PAGES {
            return DirtyTag::NONE;
        }
        DirtyTag::from_raw(self.tags[page])
    }

    /// Set a tag on a page.
    fn set_tag(&mut self, page: usize, tag: DirtyTag) {
        if page >= MAX_PAGES {
            return;
        }
        let old = DirtyTag::from_raw(self.tags[page]);
        let new = old.set(tag);
        self.tags[page] = new.raw();

        // Update counters.
        if !old.has(DirtyTag::DIRTY) && new.has(DirtyTag::DIRTY) {
            self.dirty_count += 1;
        }
        if !old.has(DirtyTag::WRITEBACK) && new.has(DirtyTag::WRITEBACK) {
            self.writeback_count += 1;
        }
    }

    /// Clear a tag from a page.
    fn clear_tag(&mut self, page: usize, tag: DirtyTag) {
        if page >= MAX_PAGES {
            return;
        }
        let old = DirtyTag::from_raw(self.tags[page]);
        let new = old.clear(tag);
        self.tags[page] = new.raw();

        // Update counters.
        if old.has(DirtyTag::DIRTY) && !new.has(DirtyTag::DIRTY) {
            self.dirty_count = self.dirty_count.saturating_sub(1);
        }
        if old.has(DirtyTag::WRITEBACK) && !new.has(DirtyTag::WRITEBACK) {
            self.writeback_count = self.writeback_count.saturating_sub(1);
        }
    }

    /// Clear all tags from a page.
    fn clear_all(&mut self, page: usize) {
        if page >= MAX_PAGES {
            return;
        }
        let old = DirtyTag::from_raw(self.tags[page]);
        if old.has(DirtyTag::DIRTY) {
            self.dirty_count = self.dirty_count.saturating_sub(1);
        }
        if old.has(DirtyTag::WRITEBACK) {
            self.writeback_count = self.writeback_count.saturating_sub(1);
        }
        self.tags[page] = 0;
    }

    /// Find the next page at or after `start` that has any of the bits in `mask`.
    fn find_next(&self, start: usize, mask: DirtyTag) -> Option<usize> {
        for i in start..MAX_PAGES {
            if (self.tags[i] & mask.raw()) != 0 {
                return Some(i);
            }
        }
        None
    }
}

// ── WritebackIter ─────────────────────────────────────────────────────────────

/// Iterator over pages matching a tag mask within a [`DirtyMapping`].
///
/// Yields `(page_index, tag_set)` pairs in ascending page order.
pub struct WritebackIter<'a> {
    /// Reference to the page tags.
    tags: &'a PageTags,
    /// Current scan position.
    pos: usize,
    /// Tag mask to match.
    mask: DirtyTag,
    /// Maximum number of entries to yield.
    limit: usize,
    /// Number of entries yielded so far.
    yielded: usize,
}

impl<'a> WritebackIter<'a> {
    /// Create a new writeback iterator.
    fn new(tags: &'a PageTags, start: usize, mask: DirtyTag, limit: usize) -> Self {
        Self {
            tags,
            pos: start,
            mask,
            limit,
            yielded: 0,
        }
    }

    /// Advance the iterator and return the next matching page.
    pub fn next_page(&mut self) -> Option<(usize, DirtyTag)> {
        if self.yielded >= self.limit {
            return None;
        }
        if let Some(idx) = self.tags.find_next(self.pos, self.mask) {
            self.pos = idx + 1;
            self.yielded += 1;
            Some((idx, self.tags.get(idx)))
        } else {
            None
        }
    }

    /// Return how many entries have been yielded so far.
    pub fn count(&self) -> usize {
        self.yielded
    }
}

// ── DirtyMapping ──────────────────────────────────────────────────────────────

/// Dirty page tracking for a single address_space (file mapping).
///
/// Provides tag-based dirty page management, coalesced dirty range
/// computation, and writeback iteration.
pub struct DirtyMapping {
    /// Inode number this mapping belongs to.
    pub inode: u64,
    /// Per-page tag storage.
    page_tags: PageTags,
    /// Cached coalesced dirty ranges.
    dirty_ranges: [Option<DirtyRange>; MAX_DIRTY_RANGES],
    /// Number of valid dirty ranges.
    range_count: usize,
    /// Whether the dirty ranges are stale (need recomputation).
    ranges_stale: bool,
    /// Total number of pages that have ever been dirtied.
    pub total_dirtied: u64,
    /// Total number of pages written back.
    pub total_written_back: u64,
    /// Whether this mapping slot is in use.
    pub in_use: bool,
}

impl DirtyMapping {
    /// Create an empty, unused mapping.
    const fn empty() -> Self {
        const NONE_RANGE: Option<DirtyRange> = None;
        Self {
            inode: 0,
            page_tags: PageTags::new(),
            dirty_ranges: [NONE_RANGE; MAX_DIRTY_RANGES],
            range_count: 0,
            ranges_stale: true,
            total_dirtied: 0,
            total_written_back: 0,
            in_use: false,
        }
    }

    /// Mark a page as dirty.
    pub fn set_dirty(&mut self, page_index: u64) -> Result<()> {
        let pi = page_index as usize;
        if pi >= MAX_PAGES {
            return Err(Error::InvalidArgument);
        }
        if !self.page_tags.get(pi).has(DirtyTag::DIRTY) {
            self.total_dirtied += 1;
        }
        self.page_tags.set_tag(pi, DirtyTag::DIRTY);
        self.ranges_stale = true;
        Ok(())
    }

    /// Clear the dirty tag from a page (e.g., after successful writeback).
    pub fn clear_dirty(&mut self, page_index: u64) -> Result<()> {
        let pi = page_index as usize;
        if pi >= MAX_PAGES {
            return Err(Error::InvalidArgument);
        }
        self.page_tags.clear_tag(pi, DirtyTag::DIRTY);
        self.ranges_stale = true;
        Ok(())
    }

    /// Tag a dirty page for the current writeback batch.
    pub fn tag_for_writeback(&mut self, page_index: u64) -> Result<()> {
        let pi = page_index as usize;
        if pi >= MAX_PAGES {
            return Err(Error::InvalidArgument);
        }
        self.page_tags.set_tag(pi, DirtyTag::TOWRITE);
        Ok(())
    }

    /// Begin writeback for a page (transition TOWRITE -> WRITEBACK).
    pub fn begin_writeback(&mut self, page_index: u64) -> Result<()> {
        let pi = page_index as usize;
        if pi >= MAX_PAGES {
            return Err(Error::InvalidArgument);
        }
        self.page_tags.clear_tag(pi, DirtyTag::TOWRITE);
        self.page_tags.set_tag(pi, DirtyTag::WRITEBACK);
        Ok(())
    }

    /// End writeback for a page (clear WRITEBACK, optionally clear DIRTY).
    pub fn end_writeback(&mut self, page_index: u64, success: bool) -> Result<()> {
        let pi = page_index as usize;
        if pi >= MAX_PAGES {
            return Err(Error::InvalidArgument);
        }
        self.page_tags.clear_tag(pi, DirtyTag::WRITEBACK);
        if success {
            self.page_tags.clear_tag(pi, DirtyTag::DIRTY);
            self.total_written_back += 1;
            self.ranges_stale = true;
        }
        Ok(())
    }

    /// Tag a page for reclaim.
    pub fn tag_reclaim(&mut self, page_index: u64) -> Result<()> {
        let pi = page_index as usize;
        if pi >= MAX_PAGES {
            return Err(Error::InvalidArgument);
        }
        self.page_tags.set_tag(pi, DirtyTag::RECLAIM);
        Ok(())
    }

    /// Clear all tags from a page (e.g., on truncation or invalidation).
    pub fn invalidate_page(&mut self, page_index: u64) -> Result<()> {
        let pi = page_index as usize;
        if pi >= MAX_PAGES {
            return Err(Error::InvalidArgument);
        }
        self.page_tags.clear_all(pi);
        self.ranges_stale = true;
        Ok(())
    }

    /// Check whether a page is dirty.
    pub fn is_dirty(&self, page_index: u64) -> bool {
        let pi = page_index as usize;
        if pi >= MAX_PAGES {
            return false;
        }
        self.page_tags.get(pi).has(DirtyTag::DIRTY)
    }

    /// Check whether a page is under writeback.
    pub fn is_writeback(&self, page_index: u64) -> bool {
        let pi = page_index as usize;
        if pi >= MAX_PAGES {
            return false;
        }
        self.page_tags.get(pi).has(DirtyTag::WRITEBACK)
    }

    /// Get the tag set for a page.
    pub fn page_tags(&self, page_index: u64) -> DirtyTag {
        let pi = page_index as usize;
        self.page_tags.get(pi)
    }

    /// Return the number of dirty pages.
    pub fn dirty_count(&self) -> u32 {
        self.page_tags.dirty_count
    }

    /// Return the number of pages under writeback.
    pub fn writeback_count(&self) -> u32 {
        self.page_tags.writeback_count
    }

    /// Return the overall dirty state.
    pub fn state(&self) -> DirtyState {
        let has_dirty = self.page_tags.dirty_count > 0;
        let has_wb = self.page_tags.writeback_count > 0;
        match (has_dirty, has_wb) {
            (false, false) => DirtyState::Clean,
            (true, false) => DirtyState::Dirty,
            (false, true) => DirtyState::Writeback,
            (true, true) => DirtyState::DirtyAndWriteback,
        }
    }

    /// Create a writeback iterator that scans pages with the given tag mask.
    pub fn iter_tagged(&self, mask: DirtyTag, limit: usize) -> WritebackIter<'_> {
        WritebackIter::new(&self.page_tags, 0, mask, limit)
    }

    /// Recompute coalesced dirty ranges.
    ///
    /// Scans the page tags and produces contiguous runs of dirty pages.
    pub fn recompute_ranges(&mut self) -> usize {
        self.range_count = 0;
        let mut i = 0usize;

        while i < MAX_PAGES && self.range_count < MAX_DIRTY_RANGES {
            if let Some(start) = self.page_tags.find_next(i, DirtyTag::DIRTY) {
                let mut end = start + 1;
                while end < MAX_PAGES && self.page_tags.get(end).has(DirtyTag::DIRTY) {
                    end += 1;
                }
                let count = (end - start) as u32;
                self.dirty_ranges[self.range_count] = Some(DirtyRange::new(start as u64, count));
                self.range_count += 1;
                i = end;
            } else {
                break;
            }
        }

        self.ranges_stale = false;
        self.range_count
    }

    /// Get the coalesced dirty ranges (recomputing if stale).
    pub fn dirty_ranges(&mut self) -> &[Option<DirtyRange>] {
        if self.ranges_stale {
            self.recompute_ranges();
        }
        &self.dirty_ranges[..self.range_count]
    }

    /// Tag all dirty pages for writeback in one pass.
    ///
    /// Returns the number of pages tagged.
    pub fn tag_all_dirty_for_writeback(&mut self) -> u32 {
        let mut count = 0u32;
        for i in 0..MAX_PAGES {
            if self.page_tags.get(i).has(DirtyTag::DIRTY)
                && !self.page_tags.get(i).has(DirtyTag::WRITEBACK)
            {
                self.page_tags.set_tag(i, DirtyTag::TOWRITE);
                count += 1;
            }
        }
        count
    }
}

// ── DirtyMappingTable ─────────────────────────────────────────────────────────

/// Global table of dirty mappings, one per address_space / inode.
pub struct DirtyMappingTable {
    /// Per-inode dirty mappings.
    mappings: [DirtyMapping; MAX_MAPPINGS],
    /// Number of active mappings.
    active_count: usize,
}

impl DirtyMappingTable {
    /// Create an empty mapping table.
    pub fn new() -> Self {
        Self {
            mappings: [const { DirtyMapping::empty() }; MAX_MAPPINGS],
            active_count: 0,
        }
    }

    /// Get or create a dirty mapping for an inode.
    pub fn get_or_create(&mut self, inode: u64) -> Result<usize> {
        // Look for existing.
        for (idx, m) in self.mappings.iter().enumerate() {
            if m.in_use && m.inode == inode {
                return Ok(idx);
            }
        }

        // Allocate new.
        let (idx, slot) = self
            .mappings
            .iter_mut()
            .enumerate()
            .find(|(_, m)| !m.in_use)
            .ok_or(Error::OutOfMemory)?;

        slot.inode = inode;
        slot.in_use = true;
        slot.ranges_stale = true;
        self.active_count += 1;
        Ok(idx)
    }

    /// Get a reference to a mapping by index.
    pub fn get(&self, idx: usize) -> Result<&DirtyMapping> {
        if idx >= MAX_MAPPINGS || !self.mappings[idx].in_use {
            return Err(Error::NotFound);
        }
        Ok(&self.mappings[idx])
    }

    /// Get a mutable reference to a mapping by index.
    pub fn get_mut(&mut self, idx: usize) -> Result<&mut DirtyMapping> {
        if idx >= MAX_MAPPINGS || !self.mappings[idx].in_use {
            return Err(Error::NotFound);
        }
        Ok(&mut self.mappings[idx])
    }

    /// Release a mapping (e.g., when inode is evicted).
    pub fn release(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_MAPPINGS || !self.mappings[idx].in_use {
            return Err(Error::NotFound);
        }
        self.mappings[idx].in_use = false;
        self.active_count = self.active_count.saturating_sub(1);
        Ok(())
    }

    /// Return the number of active mappings.
    pub fn active_count(&self) -> usize {
        self.active_count
    }

    /// Return total dirty pages across all mappings.
    pub fn total_dirty_pages(&self) -> u64 {
        self.mappings
            .iter()
            .filter(|m| m.in_use)
            .map(|m| m.page_tags.dirty_count as u64)
            .sum()
    }

    /// Return total pages under writeback across all mappings.
    pub fn total_writeback_pages(&self) -> u64 {
        self.mappings
            .iter()
            .filter(|m| m.in_use)
            .map(|m| m.page_tags.writeback_count as u64)
            .sum()
    }
}

impl Default for DirtyMappingTable {
    fn default() -> Self {
        Self::new()
    }
}
