// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page cache read/write/invalidate operations.
//!
//! Provides high-level entry points for populating the page cache from a
//! backing store, writing dirty pages, and invalidating cached pages on
//! truncate/unmap. Mirrors Linux's `address_space_operations`.

use oncrix_lib::{Error, Result};

/// Page size in bytes (4 KiB).
pub const PAGE_SIZE: usize = 4096;

/// Maximum pages managed by a single address space object.
pub const MAX_PAGES: usize = 512;

/// State of a page in the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageState {
    /// Slot is free.
    Free,
    /// Page is clean and up-to-date.
    Clean,
    /// Page has been modified and needs writeback.
    Dirty,
    /// Page is currently being read from disk.
    Locked,
    /// Page is currently being written to disk.
    Writeback,
}

/// A single page cache entry.
#[derive(Debug, Clone, Copy)]
pub struct CachedPage {
    /// File offset index (page number = offset / PAGE_SIZE).
    pub index: u64,
    /// Inode this page belongs to.
    pub ino: u64,
    /// Superblock of the owning filesystem.
    pub sb_id: u64,
    /// Page state.
    pub state: PageState,
    /// Physical frame / data buffer index (into a frame pool).
    pub frame: u32,
    /// Number of outstanding users of this page.
    pub refcount: u16,
}

impl CachedPage {
    /// Create a free (empty) page slot.
    pub const fn free() -> Self {
        Self {
            index: 0,
            ino: 0,
            sb_id: 0,
            state: PageState::Free,
            frame: 0,
            refcount: 0,
        }
    }
}

impl Default for CachedPage {
    fn default() -> Self {
        Self::free()
    }
}

/// Address space operations that a filesystem must implement.
pub trait AddressSpaceOps {
    /// Read a page from the backing store into the page cache.
    ///
    /// `frame` is a pre-allocated buffer index; the implementation fills it.
    fn read_page(&mut self, sb_id: u64, ino: u64, index: u64, frame: u32) -> Result<()>;

    /// Write a dirty page from the cache to the backing store.
    fn write_page(&mut self, sb_id: u64, ino: u64, index: u64, frame: u32) -> Result<()>;

    /// Prepare a page for writing (e.g., allocate blocks for holes).
    fn prepare_write(
        &mut self,
        sb_id: u64,
        ino: u64,
        index: u64,
        offset_in_page: u32,
        len: u32,
    ) -> Result<()>;

    /// Commit a written page (update size, timestamps).
    fn commit_write(
        &mut self,
        sb_id: u64,
        ino: u64,
        index: u64,
        offset_in_page: u32,
        len: u32,
    ) -> Result<()>;

    /// Invalidate all pages in the range [start_index, end_index].
    fn invalidate_range(&mut self, sb_id: u64, ino: u64, start: u64, end: u64) -> Result<()>;

    /// Release a clean page back to the free pool.
    fn release_page(&mut self, sb_id: u64, ino: u64, index: u64) -> bool;
}

/// Read request parameters.
#[derive(Debug, Clone, Copy)]
pub struct ReadRequest {
    pub sb_id: u64,
    pub ino: u64,
    /// Starting page index.
    pub start_index: u64,
    /// Number of pages to read.
    pub nr_pages: u32,
}

/// Write request parameters.
#[derive(Debug, Clone, Copy)]
pub struct WriteRequest {
    pub sb_id: u64,
    pub ino: u64,
    /// Starting page index.
    pub start_index: u64,
    /// Byte offset within the first page.
    pub offset: u32,
    /// Total byte length of the write.
    pub length: u64,
}

/// A simple in-memory page cache table.
pub struct PageCacheTable {
    pages: [CachedPage; MAX_PAGES],
    count: usize,
    next_frame: u32,
}

impl PageCacheTable {
    /// Create an empty page cache table.
    pub fn new() -> Self {
        Self {
            pages: [const { CachedPage::free() }; MAX_PAGES],
            count: 0,
            next_frame: 0,
        }
    }

    /// Look up a page by (sb_id, ino, index).
    pub fn find(&self, sb_id: u64, ino: u64, index: u64) -> Option<&CachedPage> {
        self.pages[..self.count].iter().find(|p| {
            p.state != PageState::Free && p.sb_id == sb_id && p.ino == ino && p.index == index
        })
    }

    /// Look up a page mutably.
    pub fn find_mut(&mut self, sb_id: u64, ino: u64, index: u64) -> Option<&mut CachedPage> {
        let count = self.count;
        self.pages[..count].iter_mut().find(|p| {
            p.state != PageState::Free && p.sb_id == sb_id && p.ino == ino && p.index == index
        })
    }

    /// Allocate a new page slot.
    pub fn alloc_page(&mut self, sb_id: u64, ino: u64, index: u64) -> Result<&mut CachedPage> {
        if self.count >= MAX_PAGES {
            // Try to evict a clean page.
            self.evict_clean_page()?;
        }
        let frame = self.next_frame;
        self.next_frame = self.next_frame.wrapping_add(1);
        let idx = self.count;
        self.pages[idx] = CachedPage {
            index,
            ino,
            sb_id,
            state: PageState::Locked,
            frame,
            refcount: 1,
        };
        self.count += 1;
        Ok(&mut self.pages[idx])
    }

    /// Evict the first clean, unreferenced page.
    fn evict_clean_page(&mut self) -> Result<()> {
        for i in 0..self.count {
            if self.pages[i].state == PageState::Clean && self.pages[i].refcount == 0 {
                // Compact: swap with last.
                let last = self.count - 1;
                self.pages.swap(i, last);
                self.pages[last] = CachedPage::free();
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Mark a page dirty.
    pub fn mark_dirty(&mut self, sb_id: u64, ino: u64, index: u64) -> Result<()> {
        let page = self.find_mut(sb_id, ino, index).ok_or(Error::NotFound)?;
        page.state = PageState::Dirty;
        Ok(())
    }

    /// Invalidate all pages in an index range for a given inode.
    pub fn invalidate_range(&mut self, sb_id: u64, ino: u64, start: u64, end: u64) -> u32 {
        let mut removed = 0u32;
        for page in self.pages[..self.count].iter_mut() {
            if page.sb_id == sb_id
                && page.ino == ino
                && page.index >= start
                && page.index <= end
                && page.state != PageState::Free
            {
                *page = CachedPage::free();
                removed += 1;
            }
        }
        // Compact the array.
        self.pages[..self.count].sort_unstable_by_key(|p| {
            if p.state == PageState::Free {
                u64::MAX
            } else {
                p.index
            }
        });
        self.count = self.count.saturating_sub(removed as usize);
        removed
    }

    /// Return the number of dirty pages for the given inode.
    pub fn dirty_count(&self, sb_id: u64, ino: u64) -> u32 {
        self.pages[..self.count]
            .iter()
            .filter(|p| p.sb_id == sb_id && p.ino == ino && p.state == PageState::Dirty)
            .count() as u32
    }

    /// Return total cached page count.
    pub fn total_count(&self) -> usize {
        self.count
    }
}

impl Default for PageCacheTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Perform a readahead: enqueue `nr_pages` pages starting at `start_index`
/// into Locked state. The caller is responsible for actually reading data via
/// `AddressSpaceOps::read_page`.
pub fn readahead_pages(
    cache: &mut PageCacheTable,
    sb_id: u64,
    ino: u64,
    start_index: u64,
    nr_pages: u32,
) -> Result<u32> {
    let mut inserted = 0u32;
    for i in 0..nr_pages as u64 {
        let index = start_index + i;
        if cache.find(sb_id, ino, index).is_some() {
            continue; // Already cached.
        }
        cache.alloc_page(sb_id, ino, index)?;
        inserted += 1;
    }
    Ok(inserted)
}

/// Write back all dirty pages for a given inode using the provided write function.
///
/// Returns the number of pages written.
pub fn writeback_inode_pages<F>(
    cache: &mut PageCacheTable,
    sb_id: u64,
    ino: u64,
    mut write_fn: F,
) -> Result<u32>
where
    F: FnMut(u64, u32) -> Result<()>,
{
    let mut written = 0u32;
    for page in cache.pages.iter_mut() {
        if page.sb_id == sb_id && page.ino == ino && page.state == PageState::Dirty {
            page.state = PageState::Writeback;
            write_fn(page.index, page.frame)?;
            page.state = PageState::Clean;
            written += 1;
        }
    }
    Ok(written)
}
