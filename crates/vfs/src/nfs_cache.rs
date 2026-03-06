// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NFS attribute and data cache.
//!
//! The NFS cache layer reduces network round-trips by holding:
//! - **Attribute cache**: file metadata (size, mtime, ctime, mode) with a
//!   configurable timeout. Stale entries trigger a fresh GETATTR.
//! - **Data page cache**: file data pages keyed by (file_handle, page_index).
//!   Invalidated on detected server-side changes.
//!
//! # Design
//!
//! - [`NfsAttr`] — cached file attributes
//! - [`NfsCacheEntry`] — combines attributes + page data for one inode
//! - [`NfsCache`] — fixed-size LRU-like cache for multiple inodes
//!
//! # References
//!
//! - Linux `fs/nfs/inode.c`, `fs/nfs/cache.c`
//! - RFC 7530 (NFSv4), RFC 1813 (NFSv3)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of NFS inodes tracked simultaneously.
const MAX_NFS_CACHE_ENTRIES: usize = 64;

/// Maximum data pages per cache entry.
const MAX_PAGES_PER_ENTRY: usize = 8;

/// Default attribute timeout in abstract time units (e.g., seconds × 100).
const DEFAULT_ATTR_TIMEOUT: u64 = 3_000;

/// Page size used for data caching.
pub const NFS_PAGE_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// NFS attributes
// ---------------------------------------------------------------------------

/// Cached file attributes received from the NFS server.
#[derive(Clone, Copy, Debug, Default)]
pub struct NfsAttr {
    /// File type and mode bits.
    pub mode: u32,
    /// Number of hard links.
    pub nlink: u32,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// File size in bytes.
    pub size: u64,
    /// Last access time (seconds).
    pub atime: u64,
    /// Last modification time (seconds).
    pub mtime: u64,
    /// Metadata change time (seconds).
    pub ctime: u64,
    /// File generation number (changes on hard-link removal + reuse).
    pub file_generation: u64,
    /// File system-specific inode number.
    pub fileid: u64,
}

// ---------------------------------------------------------------------------
// Data page
// ---------------------------------------------------------------------------

/// A single cached data page for an NFS file.
#[derive(Clone, Copy)]
pub struct NfsDataPage {
    /// Index within the file (page_index × NFS_PAGE_SIZE = byte offset).
    pub page_index: u64,
    /// Cached data bytes.
    pub data: [u8; NFS_PAGE_SIZE],
    /// Number of valid bytes in `data` (0 = slot unused).
    pub valid_bytes: usize,
    /// Whether this page has been written (dirty) and not yet flushed.
    pub dirty: bool,
}

impl NfsDataPage {
    const fn empty() -> Self {
        Self {
            page_index: u64::MAX,
            data: [0u8; NFS_PAGE_SIZE],
            valid_bytes: 0,
            dirty: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Cache entry
// ---------------------------------------------------------------------------

/// Combined attribute + page-data cache entry for one NFS inode.
pub struct NfsCacheEntry {
    /// NFS file handle (simplified as 64-bit ID).
    pub fh: u64,
    /// Cached attributes.
    pub attr: NfsAttr,
    /// Absolute time at which `attr` expires.
    pub attr_expire: u64,
    /// Whether this entry slot is occupied.
    pub valid: bool,
    /// Cached data pages.
    pages: [NfsDataPage; MAX_PAGES_PER_ENTRY],
    /// Number of valid pages.
    page_count: usize,
    /// LRU counter: incremented on each access.
    lru_stamp: u64,
}

impl NfsCacheEntry {
    const fn empty() -> Self {
        Self {
            fh: 0,
            attr: NfsAttr {
                mode: 0,
                nlink: 0,
                uid: 0,
                gid: 0,
                size: 0,
                atime: 0,
                mtime: 0,
                ctime: 0,
                file_generation: 0,
                fileid: 0,
            },
            attr_expire: 0,
            valid: false,
            pages: [const { NfsDataPage::empty() }; MAX_PAGES_PER_ENTRY],
            page_count: 0,
            lru_stamp: 0,
        }
    }

    /// Return `true` if the cached attributes are still valid at `now`.
    pub fn attr_is_fresh(&self, now: u64) -> bool {
        self.valid && now < self.attr_expire
    }

    /// Update cached attributes, resetting the timeout.
    pub fn update_attr(&mut self, attr: NfsAttr, now: u64) {
        self.attr = attr;
        self.attr_expire = now + DEFAULT_ATTR_TIMEOUT;
    }

    /// Invalidate cached attributes (force revalidation on next access).
    pub fn invalidate_attr(&mut self) {
        self.attr_expire = 0;
    }

    /// Invalidate all cached data pages (e.g., after server-side write).
    pub fn invalidate_pages(&mut self) {
        for p in &mut self.pages {
            p.valid_bytes = 0;
            p.dirty = false;
            p.page_index = u64::MAX;
        }
        self.page_count = 0;
    }

    /// Look up a cached data page by its index.
    ///
    /// Returns a reference to the page data slice, or `None` on miss.
    pub fn nfs_readpage_from_cache(&self, page_index: u64) -> Option<&[u8]> {
        for p in &self.pages {
            if p.valid_bytes > 0 && p.page_index == page_index {
                return Some(&p.data[..p.valid_bytes]);
            }
        }
        None
    }

    /// Insert or update a cached page.
    ///
    /// If there is no free slot, the oldest page is evicted (FIFO).
    pub fn cache_page(&mut self, page_index: u64, data: &[u8]) -> Result<()> {
        if data.len() > NFS_PAGE_SIZE {
            return Err(Error::InvalidArgument);
        }
        // Check if already cached.
        for p in &mut self.pages {
            if p.page_index == page_index {
                p.data[..data.len()].copy_from_slice(data);
                p.valid_bytes = data.len();
                return Ok(());
            }
        }
        // Find a free slot or evict index 0 (simple FIFO).
        let slot = if self.page_count < MAX_PAGES_PER_ENTRY {
            let s = self.page_count;
            self.page_count += 1;
            s
        } else {
            // Evict first slot, shift left.
            for i in 0..MAX_PAGES_PER_ENTRY - 1 {
                self.pages[i] = self.pages[i + 1];
            }
            MAX_PAGES_PER_ENTRY - 1
        };
        self.pages[slot] = NfsDataPage::empty();
        self.pages[slot].page_index = page_index;
        self.pages[slot].data[..data.len()].copy_from_slice(data);
        self.pages[slot].valid_bytes = data.len();
        Ok(())
    }

    /// Mark a page as dirty (written locally, not yet flushed to server).
    pub fn mark_dirty(&mut self, page_index: u64) -> Result<()> {
        for p in &mut self.pages {
            if p.page_index == page_index && p.valid_bytes > 0 {
                p.dirty = true;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }
}

// ---------------------------------------------------------------------------
// NfsCache
// ---------------------------------------------------------------------------

/// NFS attribute and data cache for multiple inodes.
pub struct NfsCache {
    entries: [NfsCacheEntry; MAX_NFS_CACHE_ENTRIES],
    /// Global LRU clock.
    lru_clock: u64,
}

impl NfsCache {
    /// Create an empty NFS cache.
    pub const fn new() -> Self {
        Self {
            entries: [const { NfsCacheEntry::empty() }; MAX_NFS_CACHE_ENTRIES],
            lru_clock: 0,
        }
    }

    /// Revalidate the inode with file handle `fh` at time `now`.
    ///
    /// If the attribute cache is still fresh, returns the cached attributes.
    /// Otherwise, the caller must perform a network GETATTR and call
    /// `update_attr`.
    ///
    /// Returns `Ok(Some(&NfsAttr))` on cache hit, `Ok(None)` on miss.
    pub fn nfs_revalidate_inode(&mut self, fh: u64, now: u64) -> Result<Option<NfsAttr>> {
        self.lru_clock += 1;
        let clock = self.lru_clock;
        if let Some(e) = self.find_entry_mut(fh) {
            e.lru_stamp = clock;
            if e.attr_is_fresh(now) {
                return Ok(Some(e.attr));
            }
            // Stale: signal caller to perform a network GETATTR.
            e.attr_expire = 0;
            return Ok(None);
        }
        Ok(None)
    }

    /// Update cached attributes for `fh` after a successful GETATTR.
    ///
    /// If no entry exists for `fh`, one is allocated (evicting LRU if full).
    pub fn update_attr(&mut self, fh: u64, attr: NfsAttr, now: u64) -> Result<()> {
        self.lru_clock += 1;
        let clock = self.lru_clock;

        if let Some(idx) = self.find_index(fh) {
            self.entries[idx].update_attr(attr, now);
            self.entries[idx].lru_stamp = clock;
            return Ok(());
        }

        // Allocate a new slot.
        let idx = self.alloc_slot()?;
        self.entries[idx].fh = fh;
        self.entries[idx].valid = true;
        self.entries[idx].update_attr(attr, now);
        self.entries[idx].lru_stamp = clock;
        self.entries[idx].page_count = 0;
        Ok(())
    }

    /// Read page `page_index` of inode `fh` from the cache.
    ///
    /// Returns the cached data slice or `Err(NotFound)` on miss.
    pub fn nfs_readpage_from_cache(&mut self, fh: u64, page_index: u64) -> Result<&[u8]> {
        self.lru_clock += 1;
        let clock = self.lru_clock;
        let idx = self.find_index(fh).ok_or(Error::NotFound)?;
        self.entries[idx].lru_stamp = clock;
        self.entries[idx]
            .nfs_readpage_from_cache(page_index)
            .ok_or(Error::NotFound)
    }

    /// Cache `data` as page `page_index` of inode `fh`.
    pub fn cache_page(&mut self, fh: u64, page_index: u64, data: &[u8]) -> Result<()> {
        let idx = self.find_index(fh).ok_or(Error::NotFound)?;
        self.entries[idx].cache_page(page_index, data)
    }

    /// Invalidate all cached data for `fh` (e.g., after a server-side write).
    pub fn cache_invalidate(&mut self, fh: u64) {
        if let Some(e) = self.find_entry_mut(fh) {
            e.invalidate_attr();
            e.invalidate_pages();
        }
    }

    /// Remove the cache entry for `fh` entirely.
    pub fn cache_remove(&mut self, fh: u64) {
        for e in &mut self.entries {
            if e.valid && e.fh == fh {
                *e = NfsCacheEntry::empty();
                return;
            }
        }
    }

    // ── Private helpers ────────────────────────────────────────────

    fn find_entry_mut(&mut self, fh: u64) -> Option<&mut NfsCacheEntry> {
        self.entries.iter_mut().find(|e| e.valid && e.fh == fh)
    }

    fn find_index(&self, fh: u64) -> Option<usize> {
        self.entries.iter().position(|e| e.valid && e.fh == fh)
    }

    /// Allocate a new slot, evicting the least-recently-used entry if full.
    fn alloc_slot(&mut self) -> Result<usize> {
        // First, try a free slot.
        if let Some(idx) = self.entries.iter().position(|e| !e.valid) {
            return Ok(idx);
        }
        // Evict LRU.
        let lru_idx = self
            .entries
            .iter()
            .enumerate()
            .min_by_key(|(_, e)| e.lru_stamp)
            .map(|(i, _)| i)
            .ok_or(Error::OutOfMemory)?;
        self.entries[lru_idx] = NfsCacheEntry::empty();
        Ok(lru_idx)
    }
}
