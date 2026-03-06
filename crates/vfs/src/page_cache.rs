// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VFS page cache for caching file data in memory.
//!
//! Provides a fixed-size cache of file pages indexed by (inode, page_index).
//! Supports LRU eviction, dirty page tracking for write-back, and
//! sequential read-ahead detection.

use oncrix_lib::{Error, Result};

/// Size of a single cached page in bytes.
pub const PAGE_SIZE: usize = 4096;

/// Maximum number of pages the cache can hold.
const MAX_CACHED_PAGES: usize = 512;

/// Maximum number of distinct inodes tracked by the cache.
const _MAX_INODES_TRACKED: usize = 64;

/// Default read-ahead window size in pages.
const DEFAULT_READAHEAD_WINDOW: usize = 4;

/// Threshold of sequential accesses before read-ahead activates.
const SEQUENTIAL_THRESHOLD: u32 = 2;

/// A single cached page of file data.
pub struct CachedPage {
    /// Inode number that owns this page.
    inode: u64,
    /// Page index within the file (file_offset / PAGE_SIZE).
    page_index: u64,
    /// Page data buffer.
    data: [u8; PAGE_SIZE],
    /// Whether this page has been modified since last flush.
    dirty: bool,
    /// Tick value of last access, used for LRU eviction.
    access_tick: u64,
    /// Number of active references to this page.
    ref_count: u32,
    /// Whether this slot is occupied.
    in_use: bool,
}

impl CachedPage {
    /// Create an empty, unused page slot.
    const fn empty() -> Self {
        Self {
            inode: 0,
            page_index: 0,
            data: [0; PAGE_SIZE],
            dirty: false,
            access_tick: 0,
            ref_count: 0,
            in_use: false,
        }
    }
}

/// Statistics about page cache usage.
#[derive(Debug, Clone, Copy)]
pub struct CacheStats {
    /// Total page slots in the cache.
    pub total_pages: usize,
    /// Number of occupied page slots.
    pub used_pages: usize,
    /// Number of dirty (modified) pages.
    pub dirty_pages: usize,
    /// Number of cache lookup hits.
    pub hit_count: u64,
    /// Number of cache lookup misses.
    pub miss_count: u64,
}

/// Iterator over dirty page slots that need write-back.
pub struct DirtyPageIter<'a> {
    /// Reference to the page cache pages array.
    pages: &'a [CachedPage; MAX_CACHED_PAGES],
    /// Current iteration index.
    pos: usize,
}

impl<'a> DirtyPageIter<'a> {
    /// Advance to the next dirty page slot.
    ///
    /// Returns `Some((slot, inode, page_index, &data))` for each
    /// dirty page, or `None` when iteration is complete.
    pub fn next_dirty(&mut self) -> Option<(usize, u64, u64, &'a [u8; PAGE_SIZE])> {
        while self.pos < MAX_CACHED_PAGES {
            let idx = self.pos;
            self.pos = self.pos.saturating_add(1);
            let page = &self.pages[idx];
            if page.in_use && page.dirty {
                return Some((idx, page.inode, page.page_index, &page.data));
            }
        }
        None
    }
}

/// Fixed-size page cache for VFS file data.
///
/// Caches up to [`MAX_CACHED_PAGES`] pages of file data indexed by
/// (inode, page_index). Uses LRU eviction when full and tracks
/// dirty pages for write-back.
pub struct PageCache {
    /// Page slot storage.
    pages: [CachedPage; MAX_CACHED_PAGES],
    /// Cache hit counter.
    hit_count: u64,
    /// Cache miss counter.
    miss_count: u64,
}

impl Default for PageCache {
    fn default() -> Self {
        Self::new()
    }
}

impl PageCache {
    /// Create a new, empty page cache.
    pub const fn new() -> Self {
        // Use a const block to initialize the array without Copy.
        const EMPTY: CachedPage = CachedPage::empty();
        Self {
            pages: [EMPTY; MAX_CACHED_PAGES],
            hit_count: 0,
            miss_count: 0,
        }
    }

    /// Look up a cached page by inode and page index.
    ///
    /// Returns `Some(slot_index)` if found, `None` otherwise.
    /// Updates hit/miss counters accordingly.
    pub fn lookup(&mut self, inode: u64, page_index: u64) -> Option<usize> {
        for i in 0..MAX_CACHED_PAGES {
            let page = &self.pages[i];
            if page.in_use && page.inode == inode && page.page_index == page_index {
                self.hit_count = self.hit_count.saturating_add(1);
                return Some(i);
            }
        }
        self.miss_count = self.miss_count.saturating_add(1);
        None
    }

    /// Insert a page into the cache.
    ///
    /// If a page with the same (inode, page_index) already exists,
    /// it is overwritten. If the cache is full, the least recently
    /// used unreferenced page is evicted. Returns the slot index.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `data` length exceeds `PAGE_SIZE`.
    /// - `Busy` if all unreferenced pages are dirty and cannot be
    ///   evicted without flushing first.
    /// - `OutOfMemory` if no eviction candidate is available.
    pub fn insert(&mut self, inode: u64, page_index: u64, data: &[u8], tick: u64) -> Result<usize> {
        if data.len() > PAGE_SIZE {
            return Err(Error::InvalidArgument);
        }

        // Check if this page is already cached; overwrite it.
        for i in 0..MAX_CACHED_PAGES {
            let page = &self.pages[i];
            if page.in_use && page.inode == inode && page.page_index == page_index {
                return self.fill_slot(i, inode, page_index, data, tick);
            }
        }

        // Find a free slot.
        for i in 0..MAX_CACHED_PAGES {
            if !self.pages[i].in_use {
                return self.fill_slot(i, inode, page_index, data, tick);
            }
        }

        // Cache full — evict LRU unreferenced page.
        let slot = self.find_eviction_candidate()?;
        self.fill_slot(slot, inode, page_index, data, tick)
    }

    /// Read data from a cached page slot into `buf`.
    ///
    /// Reads up to `buf.len()` bytes starting at `offset` within the
    /// page. Returns the number of bytes actually copied.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `slot` is out of range or `offset`
    ///   exceeds `PAGE_SIZE`.
    /// - `NotFound` if the slot is not in use.
    pub fn read(&self, slot: usize, offset: usize, buf: &mut [u8]) -> Result<usize> {
        let page = self.get_page(slot)?;
        if offset >= PAGE_SIZE {
            return Err(Error::InvalidArgument);
        }
        let available = PAGE_SIZE.saturating_sub(offset);
        let to_copy = if buf.len() < available {
            buf.len()
        } else {
            available
        };
        buf[..to_copy].copy_from_slice(&page.data[offset..offset + to_copy]);
        Ok(to_copy)
    }

    /// Write data to a cached page slot, marking it dirty.
    ///
    /// Writes up to `data.len()` bytes starting at `offset` within
    /// the page. Returns the number of bytes actually written.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `slot` is out of range or `offset`
    ///   exceeds `PAGE_SIZE`.
    /// - `NotFound` if the slot is not in use.
    pub fn write(&mut self, slot: usize, offset: usize, data: &[u8]) -> Result<usize> {
        if slot >= MAX_CACHED_PAGES {
            return Err(Error::InvalidArgument);
        }
        if !self.pages[slot].in_use {
            return Err(Error::NotFound);
        }
        if offset >= PAGE_SIZE {
            return Err(Error::InvalidArgument);
        }
        let available = PAGE_SIZE.saturating_sub(offset);
        let to_copy = if data.len() < available {
            data.len()
        } else {
            available
        };
        self.pages[slot].data[offset..offset + to_copy].copy_from_slice(&data[..to_copy]);
        self.pages[slot].dirty = true;
        Ok(to_copy)
    }

    /// Invalidate (remove) all cached pages for an inode.
    pub fn invalidate(&mut self, inode: u64) {
        for i in 0..MAX_CACHED_PAGES {
            if self.pages[i].in_use && self.pages[i].inode == inode {
                self.pages[i] = CachedPage::empty();
            }
        }
    }

    /// Invalidate (remove) a specific cached page.
    pub fn invalidate_page(&mut self, inode: u64, page_index: u64) {
        for i in 0..MAX_CACHED_PAGES {
            let page = &self.pages[i];
            if page.in_use && page.inode == inode && page.page_index == page_index {
                self.pages[i] = CachedPage::empty();
                return;
            }
        }
    }

    /// Return an iterator over dirty pages that need write-back.
    ///
    /// The caller should iterate with [`DirtyPageIter::next_dirty`],
    /// perform the I/O, then call [`mark_clean`](Self::mark_clean)
    /// on each successfully written slot.
    pub fn flush_dirty(&self) -> DirtyPageIter<'_> {
        DirtyPageIter {
            pages: &self.pages,
            pos: 0,
        }
    }

    /// Mark a cached page slot as clean (no longer dirty).
    ///
    /// Call this after successfully writing the page back to storage.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `slot` is out of range.
    /// - `NotFound` if the slot is not in use.
    pub fn mark_clean(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_CACHED_PAGES {
            return Err(Error::InvalidArgument);
        }
        if !self.pages[slot].in_use {
            return Err(Error::NotFound);
        }
        self.pages[slot].dirty = false;
        Ok(())
    }

    /// Update the access tick of a cached page for LRU tracking.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `slot` is out of range.
    /// - `NotFound` if the slot is not in use.
    pub fn touch(&mut self, slot: usize, tick: u64) -> Result<()> {
        let page = self.get_page_mut(slot)?;
        page.access_tick = tick;
        Ok(())
    }

    /// Return current cache statistics.
    pub fn stats(&self) -> CacheStats {
        let mut used: usize = 0;
        let mut dirty: usize = 0;
        for i in 0..MAX_CACHED_PAGES {
            if self.pages[i].in_use {
                used = used.saturating_add(1);
                if self.pages[i].dirty {
                    dirty = dirty.saturating_add(1);
                }
            }
        }
        CacheStats {
            total_pages: MAX_CACHED_PAGES,
            used_pages: used,
            dirty_pages: dirty,
            hit_count: self.hit_count,
            miss_count: self.miss_count,
        }
    }

    /// Fill a slot with page data.
    fn fill_slot(
        &mut self,
        slot: usize,
        inode: u64,
        page_index: u64,
        data: &[u8],
        tick: u64,
    ) -> Result<usize> {
        let page = &mut self.pages[slot];
        page.inode = inode;
        page.page_index = page_index;
        page.data = [0; PAGE_SIZE];
        page.data[..data.len()].copy_from_slice(data);
        page.dirty = false;
        page.access_tick = tick;
        page.ref_count = 0;
        page.in_use = true;
        Ok(slot)
    }

    /// Find the best LRU eviction candidate.
    ///
    /// Prefers unreferenced clean pages with the oldest access tick.
    /// If only dirty unreferenced pages remain, returns `Busy` so
    /// the caller can flush first.
    fn find_eviction_candidate(&self) -> Result<usize> {
        let mut best_clean: Option<(usize, u64)> = None;
        let mut best_dirty: Option<(usize, u64)> = None;

        for i in 0..MAX_CACHED_PAGES {
            let page = &self.pages[i];
            if !page.in_use || page.ref_count != 0 {
                continue;
            }
            let entry = &mut if page.dirty {
                &mut best_dirty
            } else {
                &mut best_clean
            };
            match entry {
                Some((_, tick)) if page.access_tick < *tick => {
                    **entry = Some((i, page.access_tick));
                }
                None => {
                    **entry = Some((i, page.access_tick));
                }
                _ => {}
            }
        }

        if let Some((slot, _)) = best_clean {
            return Ok(slot);
        }
        if best_dirty.is_some() {
            // Dirty pages exist but need flushing first.
            return Err(Error::Busy);
        }
        // All pages are referenced — truly out of memory.
        Err(Error::OutOfMemory)
    }

    /// Get an immutable reference to an in-use page slot.
    fn get_page(&self, slot: usize) -> Result<&CachedPage> {
        if slot >= MAX_CACHED_PAGES {
            return Err(Error::InvalidArgument);
        }
        if !self.pages[slot].in_use {
            return Err(Error::NotFound);
        }
        Ok(&self.pages[slot])
    }

    /// Get a mutable reference to an in-use page slot.
    fn get_page_mut(&mut self, slot: usize) -> Result<&mut CachedPage> {
        if slot >= MAX_CACHED_PAGES {
            return Err(Error::InvalidArgument);
        }
        if !self.pages[slot].in_use {
            return Err(Error::NotFound);
        }
        Ok(&mut self.pages[slot])
    }
}

/// Sequential read-ahead detector and advisor.
///
/// Tracks file access patterns and advises when prefetching
/// additional pages would be beneficial. Detects sequential reads
/// and expands the read-ahead window accordingly.
pub struct ReadAhead {
    /// Number of pages to prefetch on sequential access.
    window_size: usize,
    /// Last page index that was accessed.
    last_page_index: u64,
    /// Count of consecutive sequential accesses detected.
    sequential_count: u32,
    /// Whether any access has been recorded yet.
    has_previous: bool,
}

impl Default for ReadAhead {
    fn default() -> Self {
        Self::new()
    }
}

impl ReadAhead {
    /// Create a new read-ahead tracker with the default window.
    pub const fn new() -> Self {
        Self {
            window_size: DEFAULT_READAHEAD_WINDOW,
            last_page_index: 0,
            sequential_count: 0,
            has_previous: false,
        }
    }

    /// Create a new read-ahead tracker with a custom window size.
    ///
    /// `window_size` is clamped to at least 1 page.
    pub const fn with_window(window_size: usize) -> Self {
        let ws = if window_size == 0 { 1 } else { window_size };
        Self {
            window_size: ws,
            last_page_index: 0,
            sequential_count: 0,
            has_previous: false,
        }
    }

    /// Check whether read-ahead should be triggered for the given
    /// page index.
    ///
    /// Returns `true` if the recent access pattern is sequential
    /// and prefetching is likely beneficial.
    pub fn should_readahead(&self, page_index: u64) -> bool {
        if !self.has_previous {
            return false;
        }
        // Sequential if this is the next page after the last one.
        let is_next = page_index == self.last_page_index.saturating_add(1);
        is_next && self.sequential_count >= SEQUENTIAL_THRESHOLD
    }

    /// Record a page access to update the sequential detector.
    pub fn record_access(&mut self, page_index: u64) {
        if !self.has_previous {
            self.has_previous = true;
            self.last_page_index = page_index;
            self.sequential_count = 0;
            return;
        }
        if page_index == self.last_page_index.saturating_add(1) {
            self.sequential_count = self.sequential_count.saturating_add(1);
        } else {
            self.sequential_count = 0;
        }
        self.last_page_index = page_index;
    }

    /// Compute the range of page indices to prefetch.
    ///
    /// Returns `(start, end)` where `start` is the first page to
    /// prefetch (exclusive of `page_index` itself) and `end` is
    /// one past the last page to prefetch.
    pub fn readahead_range(&self, page_index: u64) -> (u64, u64) {
        let start = page_index.saturating_add(1);
        let end = start.saturating_add(self.window_size as u64);
        (start, end)
    }

    /// Return the current read-ahead window size.
    pub const fn window_size(&self) -> usize {
        self.window_size
    }

    /// Return the number of consecutive sequential accesses.
    pub const fn sequential_count(&self) -> u32 {
        self.sequential_count
    }
}
