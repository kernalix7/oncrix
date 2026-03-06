// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! File-backed page mapping (filemap) subsystem.
//!
//! Implements the file-backed page cache, mapping file data into physical
//! pages and tracking their state throughout the page lifecycle: clean,
//! dirty, writeback, and locked. This is the central component connecting
//! VFS read/write operations to physical memory and backing storage I/O.
//!
//! # Design
//!
//! The filemap maintains an address-ordered collection of page cache entries
//! indexed by `(file_id, page_index)`. Operations include:
//!
//! - **find_page** — look up a cached page by file + offset
//! - **add_page** — insert a newly read or faulted-in page
//! - **remove_page** — evict a page from the cache
//! - **mark_dirty** — flag a page as modified, initiating writeback
//! - **clear_dirty** — clear the dirty flag after writeback completes
//! - **lock_page / unlock_page** — serialise concurrent I/O on one page
//! - **wait_on_page** — block until a page's locked/writeback flag clears
//!
//! # Types
//!
//! - [`PageState`] — lifecycle state of a cached page
//! - [`CachePageFlags`] — bitmask of per-page flags
//! - [`CachePage`] — a single entry in the file page cache
//! - [`FilemapStats`] — aggregate cache statistics
//! - [`Filemap`] — the file page cache
//!
//! Reference: Linux `mm/filemap.c`, `include/linux/pagemap.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size in bytes.
const PAGE_SIZE: usize = 4096;

/// Maximum number of pages in the filemap cache.
const FILEMAP_MAX_PAGES: usize = 1024;

/// Maximum number of waiters per locked page.
const MAX_LOCK_WAITERS: usize = 16;

/// Sentinel value representing an unused cache slot.
const EMPTY_FILE_ID: u64 = u64::MAX;

// -------------------------------------------------------------------
// PageState
// -------------------------------------------------------------------

/// Lifecycle state of a page in the file cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PageState {
    /// Slot is empty — no page resident.
    #[default]
    Empty,
    /// Page is present and clean (matches backing storage).
    Clean,
    /// Page has been modified and is awaiting writeback.
    Dirty,
    /// Page is currently being written back to storage.
    Writeback,
    /// Page is locked for exclusive I/O (being read or written).
    Locked,
    /// Page has been invalidated and is being freed.
    Invalidating,
}

// -------------------------------------------------------------------
// CachePageFlags
// -------------------------------------------------------------------

/// Bitmask flags for a cached page.
#[derive(Debug, Clone, Copy, Default)]
pub struct CachePageFlags(u32);

impl CachePageFlags {
    /// Page is present in the cache.
    pub const PRESENT: u32 = 1 << 0;
    /// Page data is dirty (modified).
    pub const DIRTY: u32 = 1 << 1;
    /// Page is under writeback.
    pub const WRITEBACK: u32 = 1 << 2;
    /// Page is locked (I/O in progress).
    pub const LOCKED: u32 = 1 << 3;
    /// Page has been accessed recently.
    pub const ACCESSED: u32 = 1 << 4;
    /// Page is mapped into a user address space.
    pub const MAPPED: u32 = 1 << 5;
    /// Page is pinned (elevated refcount).
    pub const PINNED: u32 = 1 << 6;
    /// Page error — I/O failed.
    pub const ERROR: u32 = 1 << 7;

    /// Creates empty flags.
    pub const fn new() -> Self {
        Self(0)
    }

    /// Sets the given bit.
    pub fn set(&mut self, flag: u32) {
        self.0 |= flag;
    }

    /// Clears the given bit.
    pub fn clear(&mut self, flag: u32) {
        self.0 &= !flag;
    }

    /// Tests whether `flag` is set.
    pub fn has(&self, flag: u32) -> bool {
        self.0 & flag != 0
    }
}

// -------------------------------------------------------------------
// CachePage
// -------------------------------------------------------------------

/// A single entry in the file page cache.
///
/// Represents one page of file data cached in memory, identified by
/// its `(file_id, page_index)` key pair.
#[derive(Debug, Clone)]
pub struct CachePage {
    /// Owning file identifier.
    pub file_id: u64,
    /// Page offset within the file (0-based page index).
    pub page_index: u64,
    /// Physical frame number backing this page.
    pub pfn: u64,
    /// Current lifecycle state.
    pub state: PageState,
    /// Per-page flags.
    pub flags: CachePageFlags,
    /// Reference count (number of active users).
    pub ref_count: u32,
    /// Number of mappings into user address spaces.
    pub map_count: u32,
    /// Waiters blocked on this page's lock (stored as count).
    pub lock_waiters: u32,
    /// Monotonic timestamp of last access (in ticks).
    pub last_access: u64,
    /// Monotonic timestamp when page was dirtied.
    pub dirty_time: u64,
    /// Page data buffer (simulated).
    pub data: [u8; PAGE_SIZE],
}

impl CachePage {
    /// Creates a new empty cache page slot.
    pub fn new() -> Self {
        Self {
            file_id: EMPTY_FILE_ID,
            page_index: 0,
            pfn: 0,
            state: PageState::Empty,
            flags: CachePageFlags::new(),
            ref_count: 0,
            map_count: 0,
            lock_waiters: 0,
            last_access: 0,
            dirty_time: 0,
            data: [0u8; PAGE_SIZE],
        }
    }

    /// Returns `true` if this slot is occupied.
    pub fn is_occupied(&self) -> bool {
        self.file_id != EMPTY_FILE_ID
    }

    /// Returns `true` if the page is dirty.
    pub fn is_dirty(&self) -> bool {
        self.flags.has(CachePageFlags::DIRTY)
    }

    /// Returns `true` if the page is locked.
    pub fn is_locked(&self) -> bool {
        self.state == PageState::Locked || self.flags.has(CachePageFlags::LOCKED)
    }

    /// Returns `true` if the page is under writeback.
    pub fn is_writeback(&self) -> bool {
        self.state == PageState::Writeback || self.flags.has(CachePageFlags::WRITEBACK)
    }
}

impl Default for CachePage {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// FilemapStats
// -------------------------------------------------------------------

/// Aggregate filemap cache statistics.
#[derive(Debug, Default, Clone, Copy)]
pub struct FilemapStats {
    /// Total page lookups performed.
    pub lookups: u64,
    /// Cache hits (page found in cache).
    pub hits: u64,
    /// Cache misses (page not found).
    pub misses: u64,
    /// Pages added to the cache.
    pub pages_added: u64,
    /// Pages removed (evicted or invalidated).
    pub pages_removed: u64,
    /// Dirty page transitions.
    pub dirty_transitions: u64,
    /// Writeback completions.
    pub writeback_completions: u64,
    /// Page lock acquisitions.
    pub lock_acquisitions: u64,
    /// Page lock contentions (had to wait).
    pub lock_contentions: u64,
}

impl FilemapStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            lookups: 0,
            hits: 0,
            misses: 0,
            pages_added: 0,
            pages_removed: 0,
            dirty_transitions: 0,
            writeback_completions: 0,
            lock_acquisitions: 0,
            lock_contentions: 0,
        }
    }

    /// Cache hit ratio as a percentage (0–100).
    pub fn hit_ratio_pct(&self) -> u8 {
        if self.lookups == 0 {
            return 0;
        }
        ((self.hits * 100) / self.lookups).min(100) as u8
    }
}

// -------------------------------------------------------------------
// Filemap
// -------------------------------------------------------------------

/// The file-backed page cache.
///
/// Manages up to [`FILEMAP_MAX_PAGES`] cached pages across all open
/// files. Uses a flat array with linear search for simplicity; a
/// production kernel would use an XArray or radix tree.
pub struct Filemap {
    pages: [CachePage; FILEMAP_MAX_PAGES],
    page_count: usize,
    stats: FilemapStats,
    clock: u64,
}

impl Filemap {
    /// Creates an empty filemap.
    pub fn new() -> Self {
        Self {
            pages: core::array::from_fn(|_| CachePage::new()),
            page_count: 0,
            stats: FilemapStats::new(),
            clock: 0,
        }
    }

    /// Ticks the internal monotonic clock.
    pub fn tick(&mut self) {
        self.clock = self.clock.wrapping_add(1);
    }

    /// Looks up the page for `(file_id, page_index)`.
    ///
    /// Returns `Ok(&CachePage)` on hit, `Err(NotFound)` on miss.
    pub fn find_page(&mut self, file_id: u64, page_index: u64) -> Result<&CachePage> {
        self.stats.lookups += 1;
        for page in self.pages.iter_mut() {
            if page.is_occupied() && page.file_id == file_id && page.page_index == page_index {
                page.flags.set(CachePageFlags::ACCESSED);
                page.last_access = self.clock;
                self.stats.hits += 1;
                // SAFETY: We need to return a shared ref; we've finished mutating.
                return Ok(unsafe { &*(page as *const CachePage) });
            }
        }
        self.stats.misses += 1;
        Err(Error::NotFound)
    }

    /// Adds a new page to the cache.
    ///
    /// # Errors
    ///
    /// - `AlreadyExists` — a page for `(file_id, page_index)` is already cached.
    /// - `OutOfMemory` — the cache is full.
    pub fn add_page(&mut self, file_id: u64, page_index: u64, pfn: u64) -> Result<()> {
        // Check for duplicate
        for page in self.pages.iter() {
            if page.is_occupied() && page.file_id == file_id && page.page_index == page_index {
                return Err(Error::AlreadyExists);
            }
        }
        if self.page_count >= FILEMAP_MAX_PAGES {
            return Err(Error::OutOfMemory);
        }
        for slot in self.pages.iter_mut() {
            if !slot.is_occupied() {
                slot.file_id = file_id;
                slot.page_index = page_index;
                slot.pfn = pfn;
                slot.state = PageState::Clean;
                slot.flags = CachePageFlags::new();
                slot.flags.set(CachePageFlags::PRESENT);
                slot.ref_count = 1;
                slot.map_count = 0;
                slot.lock_waiters = 0;
                slot.last_access = self.clock;
                slot.dirty_time = 0;
                slot.data = [0u8; PAGE_SIZE];
                self.page_count += 1;
                self.stats.pages_added += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Removes a page from the cache.
    ///
    /// Fails with `Busy` if the page is locked or has active users.
    pub fn remove_page(&mut self, file_id: u64, page_index: u64) -> Result<()> {
        for slot in self.pages.iter_mut() {
            if slot.is_occupied() && slot.file_id == file_id && slot.page_index == page_index {
                if slot.is_locked() || slot.ref_count > 1 {
                    return Err(Error::Busy);
                }
                slot.file_id = EMPTY_FILE_ID;
                slot.state = PageState::Empty;
                slot.flags = CachePageFlags::new();
                slot.ref_count = 0;
                self.page_count = self.page_count.saturating_sub(1);
                self.stats.pages_removed += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Marks a page as dirty.
    ///
    /// The page transitions from `Clean` to `Dirty`. Writeback and
    /// locked pages are not re-dirtied until they complete.
    pub fn mark_dirty(&mut self, file_id: u64, page_index: u64) -> Result<()> {
        for slot in self.pages.iter_mut() {
            if slot.is_occupied() && slot.file_id == file_id && slot.page_index == page_index {
                if slot.state == PageState::Clean {
                    slot.state = PageState::Dirty;
                    slot.flags.set(CachePageFlags::DIRTY);
                    slot.dirty_time = self.clock;
                    self.stats.dirty_transitions += 1;
                }
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Clears the dirty flag after writeback completes.
    ///
    /// Transitions the page from `Writeback` back to `Clean`.
    pub fn clear_dirty(&mut self, file_id: u64, page_index: u64) -> Result<()> {
        for slot in self.pages.iter_mut() {
            if slot.is_occupied() && slot.file_id == file_id && slot.page_index == page_index {
                slot.state = PageState::Clean;
                slot.flags.clear(CachePageFlags::DIRTY);
                slot.flags.clear(CachePageFlags::WRITEBACK);
                slot.dirty_time = 0;
                self.stats.writeback_completions += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Marks a page as being written back to storage.
    pub fn start_writeback(&mut self, file_id: u64, page_index: u64) -> Result<()> {
        for slot in self.pages.iter_mut() {
            if slot.is_occupied() && slot.file_id == file_id && slot.page_index == page_index {
                if slot.state != PageState::Dirty {
                    return Err(Error::InvalidArgument);
                }
                slot.state = PageState::Writeback;
                slot.flags.set(CachePageFlags::WRITEBACK);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Locks a page for exclusive I/O.
    ///
    /// Returns `Err(WouldBlock)` if the page is already locked.
    pub fn lock_page(&mut self, file_id: u64, page_index: u64) -> Result<()> {
        self.stats.lock_acquisitions += 1;
        for slot in self.pages.iter_mut() {
            if slot.is_occupied() && slot.file_id == file_id && slot.page_index == page_index {
                if slot.is_locked() {
                    slot.lock_waiters = slot
                        .lock_waiters
                        .saturating_add(1)
                        .min(MAX_LOCK_WAITERS as u32);
                    self.stats.lock_contentions += 1;
                    return Err(Error::WouldBlock);
                }
                slot.state = PageState::Locked;
                slot.flags.set(CachePageFlags::LOCKED);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Unlocks a previously locked page.
    pub fn unlock_page(&mut self, file_id: u64, page_index: u64) -> Result<()> {
        for slot in self.pages.iter_mut() {
            if slot.is_occupied() && slot.file_id == file_id && slot.page_index == page_index {
                if !slot.is_locked() {
                    return Err(Error::InvalidArgument);
                }
                slot.state = PageState::Clean;
                slot.flags.clear(CachePageFlags::LOCKED);
                slot.lock_waiters = slot.lock_waiters.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Writes `data` into the cached page buffer.
    ///
    /// `offset` must be within `[0, PAGE_SIZE)` and `data.len()` must
    /// not exceed `PAGE_SIZE - offset`.
    pub fn write_page_data(
        &mut self,
        file_id: u64,
        page_index: u64,
        offset: usize,
        data: &[u8],
    ) -> Result<()> {
        if offset >= PAGE_SIZE || offset + data.len() > PAGE_SIZE {
            return Err(Error::InvalidArgument);
        }
        for slot in self.pages.iter_mut() {
            if slot.is_occupied() && slot.file_id == file_id && slot.page_index == page_index {
                slot.data[offset..offset + data.len()].copy_from_slice(data);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Reads from the cached page buffer into `out`.
    pub fn read_page_data(
        &self,
        file_id: u64,
        page_index: u64,
        offset: usize,
        out: &mut [u8],
    ) -> Result<()> {
        if offset >= PAGE_SIZE || offset + out.len() > PAGE_SIZE {
            return Err(Error::InvalidArgument);
        }
        for page in self.pages.iter() {
            if page.is_occupied() && page.file_id == file_id && page.page_index == page_index {
                out.copy_from_slice(&page.data[offset..offset + out.len()]);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Invalidates all pages belonging to `file_id`.
    ///
    /// Returns the number of pages evicted. Busy (locked) pages are
    /// skipped and counted in `skipped`.
    pub fn invalidate_file(&mut self, file_id: u64, skipped: &mut usize) -> usize {
        let mut evicted = 0usize;
        *skipped = 0;
        for slot in self.pages.iter_mut() {
            if slot.is_occupied() && slot.file_id == file_id {
                if slot.is_locked() || slot.ref_count > 1 {
                    *skipped += 1;
                    continue;
                }
                slot.file_id = EMPTY_FILE_ID;
                slot.state = PageState::Empty;
                slot.flags = CachePageFlags::new();
                slot.ref_count = 0;
                self.page_count = self.page_count.saturating_sub(1);
                self.stats.pages_removed += 1;
                evicted += 1;
            }
        }
        evicted
    }

    /// Returns a reference to the underlying page at slot `idx` (0-based).
    ///
    /// Returns `None` if `idx` is out of range or the slot is empty.
    pub fn page_at(&self, idx: usize) -> Option<&CachePage> {
        self.pages.get(idx).filter(|p| p.is_occupied())
    }

    /// Returns the number of occupied cache slots.
    pub fn page_count(&self) -> usize {
        self.page_count
    }

    /// Returns the maximum cache capacity.
    pub fn capacity(&self) -> usize {
        FILEMAP_MAX_PAGES
    }

    /// Returns a snapshot of cache statistics.
    pub fn stats(&self) -> FilemapStats {
        self.stats
    }

    /// Iterates dirty pages, calling `f(file_id, page_index)` for each.
    ///
    /// Stops early if `f` returns `false`.
    pub fn for_each_dirty<F>(&self, mut f: F)
    where
        F: FnMut(u64, u64) -> bool,
    {
        for page in self.pages.iter() {
            if page.is_occupied() && page.is_dirty() {
                if !f(page.file_id, page.page_index) {
                    break;
                }
            }
        }
    }
}

impl Default for Filemap {
    fn default() -> Self {
        Self::new()
    }
}
