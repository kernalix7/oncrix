// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ramfs address space operations (aops).
//!
//! ramfs stores all file data in anonymous memory pages. Since ramfs has no
//! backing storage, its address space operations are simpler than on-disk
//! filesystems: there is no writeback, no readahead from disk, and pages
//! are never evicted under memory pressure (ramfs has no page limits).
//!
//! # Page Allocation Strategy
//!
//! When a write extends a ramfs file, new pages are allocated from the
//! kernel page allocator. Pages are zeroed on allocation to ensure that
//! sparse regions of a file read as zeros (POSIX requirement).
//!
//! # Truncation
//!
//! When a ramfs file is truncated, pages beyond the new file size are freed
//! immediately. Partial-page truncation zeroes the tail bytes of the last page.

use oncrix_lib::{Error, Result};

/// ramfs page size (always 4 KiB).
pub const RAMFS_PAGE_SIZE: usize = 4096;

/// Maximum number of pages per ramfs file (4 GiB / 4 KiB = 1 M pages).
pub const RAMFS_MAX_PAGES: usize = 1_048_576;

/// A single page slot in the ramfs page cache.
///
/// Pages are identified by their index (file offset / page size).
#[derive(Clone, Copy, Default)]
pub struct RamfsPage {
    /// Page index (file offset >> PAGE_SHIFT).
    pub index: u64,
    /// Physical frame number of the allocated page (0 = not allocated).
    pub pfn: u64,
    /// Whether this page has been written (dirty).
    pub dirty: bool,
}

impl RamfsPage {
    /// Returns `true` if this slot is populated.
    pub const fn is_present(&self) -> bool {
        self.pfn != 0
    }
}

/// Page cache for a ramfs inode.
///
/// Tracks up to `CAP` pages. For production use, a radix tree or
/// sparse array would be used; this fixed-size array suffices for
/// the kernel stub.
pub struct RamfsPageCache<const CAP: usize> {
    pages: [RamfsPage; CAP],
    count: usize,
    /// File size in bytes.
    file_size: u64,
}

impl<const CAP: usize> Default for RamfsPageCache<CAP> {
    fn default() -> Self {
        Self {
            pages: [RamfsPage::default(); CAP],
            count: 0,
            file_size: 0,
        }
    }
}

impl<const CAP: usize> RamfsPageCache<CAP> {
    /// Creates an empty page cache.
    pub const fn new() -> Self {
        Self {
            pages: [RamfsPage {
                index: 0,
                pfn: 0,
                dirty: false,
            }; CAP],
            count: 0,
            file_size: 0,
        }
    }

    /// Returns the current file size.
    pub const fn size(&self) -> u64 {
        self.file_size
    }

    /// Looks up the page for `index`.
    pub fn find_page(&self, index: u64) -> Option<&RamfsPage> {
        self.pages[..self.count].iter().find(|p| p.index == index)
    }

    /// Looks up a mutable page for `index`.
    pub fn find_page_mut(&mut self, index: u64) -> Option<&mut RamfsPage> {
        let count = self.count;
        self.pages[..count].iter_mut().find(|p| p.index == index)
    }

    /// Inserts a new page slot (page must not already exist).
    ///
    /// `pfn` is the physical frame number of the allocated page.
    pub fn insert_page(&mut self, index: u64, pfn: u64) -> Result<()> {
        if self.count >= CAP {
            return Err(Error::OutOfMemory);
        }
        if self.find_page(index).is_some() {
            return Err(Error::AlreadyExists);
        }
        self.pages[self.count] = RamfsPage {
            index,
            pfn,
            dirty: false,
        };
        self.count += 1;
        Ok(())
    }

    /// Removes the page for `index`, returning its PFN.
    pub fn remove_page(&mut self, index: u64) -> Option<u64> {
        let pos = self.pages[..self.count]
            .iter()
            .position(|p| p.index == index)?;
        let pfn = self.pages[pos].pfn;
        // Compact the array.
        self.count -= 1;
        self.pages[pos] = self.pages[self.count];
        self.pages[self.count] = RamfsPage::default();
        Some(pfn)
    }

    /// Updates the file size after a write.
    ///
    /// Only extends; never shrinks (use `truncate` for that).
    pub fn update_size(&mut self, new_size: u64) {
        if new_size > self.file_size {
            self.file_size = new_size;
        }
    }

    /// Truncates the file to `new_size` bytes.
    ///
    /// Removes all pages beyond the new size. Returns a list of freed PFNs
    /// (caller must return them to the page allocator).
    ///
    /// If `new_size` is larger than the current size, this is a no-op
    /// (extending is done via writes).
    pub fn truncate(&mut self, new_size: u64, freed: &mut [u64; 64]) -> usize {
        if new_size >= self.file_size {
            self.file_size = new_size;
            return 0;
        }
        self.file_size = new_size;
        let cutoff_page = new_size / RAMFS_PAGE_SIZE as u64;

        let mut freed_count = 0usize;
        let mut i = 0;
        while i < self.count {
            if self.pages[i].index > cutoff_page {
                if freed_count < 64 {
                    freed[freed_count] = self.pages[i].pfn;
                    freed_count += 1;
                }
                self.count -= 1;
                self.pages[i] = self.pages[self.count];
                self.pages[self.count] = RamfsPage::default();
                // Do not increment i — check the swapped-in element.
            } else {
                i += 1;
            }
        }
        freed_count
    }

    /// Marks all pages as clean (called after a "sync" — ramfs never actually
    /// writes to disk, but dirty tracking can be used for auditing).
    pub fn clear_dirty(&mut self) {
        for p in &mut self.pages[..self.count] {
            p.dirty = false;
        }
    }

    /// Returns the number of dirty pages.
    pub fn dirty_count(&self) -> usize {
        self.pages[..self.count].iter().filter(|p| p.dirty).count()
    }

    /// Simulates reading `len` bytes at `offset` by checking which pages
    /// are present. Returns the byte range covered by a single present page,
    /// or an error if no page covers `offset`.
    pub fn read_page_range(&self, offset: u64, _len: u64) -> Result<(u64, u64)> {
        let page_idx = offset / RAMFS_PAGE_SIZE as u64;
        let page_off = offset % RAMFS_PAGE_SIZE as u64;
        let page = self.find_page(page_idx).ok_or(Error::NotFound)?;
        let available = RAMFS_PAGE_SIZE as u64 - page_off;
        Ok((page.pfn * RAMFS_PAGE_SIZE as u64 + page_off, available))
    }
}
