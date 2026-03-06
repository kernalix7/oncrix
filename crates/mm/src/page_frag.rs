// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page fragment allocator for sub-page memory allocation.
//!
//! Provides efficient allocation of small, short-lived memory regions
//! from within 4 KiB pages. This is the primary allocator for network
//! buffer headers (sk_buff data), where allocations are typically
//! 64–256 bytes and occur at very high frequency on the data path.
//!
//! # Design
//!
//! Each [`PageFragCache`] holds a reference to a single backing page
//! and bumps an offset pointer for each allocation. When the page is
//! exhausted, a new page is allocated. Reference counting ensures that
//! the backing page is freed only after all fragments are released.
//!
//! # Subsystems
//!
//! - [`PageFragCache`] — per-CPU cache holding the current backing page
//! - [`PageFrag`] — descriptor for an allocated fragment
//! - [`PageFragPool`] — pool of caches and fragment tracking
//! - [`PageFragStats`] — allocation statistics
//!
//! Reference: Linux `mm/page_frag_cache.c`,
//! `include/linux/page_frag_cache.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u16 = 4096;

/// Minimum fragment allocation size (bytes).
const MIN_FRAG_SIZE: u16 = 64;

/// Maximum fragment allocation size (entire page).
const MAX_FRAG_SIZE: u16 = PAGE_SIZE;

/// Fragment alignment (8 bytes).
const FRAG_ALIGN: u16 = 8;

/// Number of per-CPU caches.
const MAX_CACHES: usize = 32;

/// Maximum number of active fragments tracked.
const MAX_FRAGMENTS: usize = 1024;

/// Maximum reference count per backing page.
const MAX_PAGE_REF: u16 = 512;

/// Invalid fragment index sentinel.
const INVALID_FRAG: u32 = u32::MAX;

// -------------------------------------------------------------------
// PageFragCache
// -------------------------------------------------------------------

/// Per-CPU page-fragment cache.
///
/// Holds a single backing page and a bump pointer. Allocations are
/// carved out sequentially until the page is exhausted.
#[derive(Debug, Clone, Copy)]
pub struct PageFragCache {
    /// Physical address of the current backing page.
    page_phys: u64,
    /// Current offset within the page (next allocation starts here).
    offset: u16,
    /// Remaining bytes in the current page.
    remaining: u16,
    /// Bias applied to the page refcount (pre-incremented).
    pagecnt_bias: u16,
    /// Whether this cache slot is initialised.
    active: bool,
}

impl PageFragCache {
    /// Create an uninitialised cache.
    const fn empty() -> Self {
        Self {
            page_phys: 0,
            offset: 0,
            remaining: 0,
            pagecnt_bias: 0,
            active: false,
        }
    }

    /// Physical address of the backing page.
    pub const fn page_phys(&self) -> u64 {
        self.page_phys
    }

    /// Current allocation offset within the page.
    pub const fn offset(&self) -> u16 {
        self.offset
    }

    /// Remaining bytes in the page.
    pub const fn remaining(&self) -> u16 {
        self.remaining
    }

    /// Reference-count bias for the current page.
    pub const fn pagecnt_bias(&self) -> u16 {
        self.pagecnt_bias
    }

    /// Whether this cache is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Initialise the cache with a new backing page.
    fn refill(&mut self, page_phys: u64) {
        self.page_phys = page_phys;
        self.offset = 0;
        self.remaining = PAGE_SIZE;
        self.pagecnt_bias = 1; // initial reference
        self.active = true;
    }

    /// Try to allocate `size` bytes from this cache.
    ///
    /// Returns `(offset_in_page, new_remaining)` on success.
    fn try_alloc(&mut self, size: u16) -> Option<u16> {
        if !self.active || size > self.remaining {
            return None;
        }
        let alloc_offset = self.offset;
        self.offset += size;
        self.remaining -= size;
        self.pagecnt_bias += 1;
        Some(alloc_offset)
    }
}

impl Default for PageFragCache {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// PageFrag
// -------------------------------------------------------------------

/// Descriptor for a single allocated page fragment.
#[derive(Debug, Clone, Copy)]
pub struct PageFrag {
    /// Physical address of the backing page.
    phys_addr: u64,
    /// Offset within the page where this fragment starts.
    offset: u16,
    /// Size of the fragment in bytes.
    size: u16,
    /// Index of the cache that owns the backing page.
    cache_idx: u8,
    /// Whether this fragment is in use.
    active: bool,
}

impl PageFrag {
    /// Create an empty (inactive) fragment descriptor.
    const fn empty() -> Self {
        Self {
            phys_addr: 0,
            offset: 0,
            size: 0,
            cache_idx: 0,
            active: false,
        }
    }

    /// Physical address of the backing page.
    pub const fn phys_addr(&self) -> u64 {
        self.phys_addr
    }

    /// Offset within the backing page.
    pub const fn offset(&self) -> u16 {
        self.offset
    }

    /// Size of this fragment.
    pub const fn size(&self) -> u16 {
        self.size
    }

    /// Cache index that owns the backing page.
    pub const fn cache_idx(&self) -> u8 {
        self.cache_idx
    }

    /// Whether this fragment is in use.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Compute the absolute physical address of this fragment.
    pub const fn absolute_phys(&self) -> u64 {
        self.phys_addr + self.offset as u64
    }
}

impl Default for PageFrag {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// PageFragStats
// -------------------------------------------------------------------

/// Fragment allocator statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct PageFragStats {
    /// Total fragment allocations.
    pub total_alloc: u64,
    /// Total fragment frees.
    pub total_free: u64,
    /// Total backing-page allocations (refills).
    pub page_allocs: u64,
    /// Number of currently active fragments.
    pub fragments_active: u32,
}

// -------------------------------------------------------------------
// PageFragPool
// -------------------------------------------------------------------

/// Pool of per-CPU page-fragment caches and fragment tracking.
///
/// Manages [`MAX_CACHES`] caches and up to [`MAX_FRAGMENTS`] active
/// fragment descriptors.
pub struct PageFragPool {
    /// Per-CPU caches.
    caches: [PageFragCache; MAX_CACHES],
    /// Active fragments.
    fragments: [PageFrag; MAX_FRAGMENTS],
    /// Next simulated physical page address (bump allocator).
    next_page_phys: u64,
    /// Statistics.
    stats: PageFragStats,
}

impl PageFragPool {
    /// Create a new pool.
    ///
    /// `base_phys` is the starting physical address for backing pages.
    pub const fn new(base_phys: u64) -> Self {
        Self {
            caches: [const { PageFragCache::empty() }; MAX_CACHES],
            fragments: [const { PageFrag::empty() }; MAX_FRAGMENTS],
            next_page_phys: base_phys,
            stats: PageFragStats {
                total_alloc: 0,
                total_free: 0,
                page_allocs: 0,
                fragments_active: 0,
            },
        }
    }

    /// Return current statistics.
    pub const fn stats(&self) -> &PageFragStats {
        &self.stats
    }

    /// Allocate a page fragment of the given size.
    ///
    /// The size is rounded up to [`FRAG_ALIGN`] and must be between
    /// [`MIN_FRAG_SIZE`] and [`MAX_FRAG_SIZE`].
    ///
    /// `cpu_id` selects which cache to use (modulo number of caches).
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — size out of range
    /// * `OutOfMemory` — no free fragment slots or cannot allocate page
    pub fn page_frag_alloc(&mut self, cpu_id: u8, size: u16) -> Result<u32> {
        // Validate size.
        if size < MIN_FRAG_SIZE || size > MAX_FRAG_SIZE {
            return Err(Error::InvalidArgument);
        }

        // Round up to alignment.
        let aligned_size = (size + FRAG_ALIGN - 1) & !(FRAG_ALIGN - 1);
        let cache_idx = (cpu_id as usize) % MAX_CACHES;

        // Find a free fragment slot first.
        let frag_idx = self.find_free_fragment().ok_or(Error::OutOfMemory)?;

        // Try to allocate from the cache's current page.
        let alloc_offset = self.caches[cache_idx].try_alloc(aligned_size);
        let (page_phys, offset) = match alloc_offset {
            Some(off) => (self.caches[cache_idx].page_phys, off),
            None => {
                // Need a new backing page.
                self.refill_cache(cache_idx)?;
                let off = self.caches[cache_idx]
                    .try_alloc(aligned_size)
                    .ok_or(Error::OutOfMemory)?;
                (self.caches[cache_idx].page_phys, off)
            }
        };

        // Record the fragment.
        self.fragments[frag_idx] = PageFrag {
            phys_addr: page_phys,
            offset,
            size: aligned_size,
            cache_idx: cache_idx as u8,
            active: true,
        };

        self.stats.total_alloc += 1;
        self.stats.fragments_active += 1;

        Ok(frag_idx as u32)
    }

    /// Free a previously allocated page fragment.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — index out of range
    /// * `NotFound` — fragment is not active
    pub fn page_frag_free(&mut self, frag_idx: u32) -> Result<()> {
        if frag_idx as usize >= MAX_FRAGMENTS {
            return Err(Error::InvalidArgument);
        }
        let idx = frag_idx as usize;
        if !self.fragments[idx].active {
            return Err(Error::NotFound);
        }

        let cache_idx = self.fragments[idx].cache_idx as usize;
        if cache_idx < MAX_CACHES && self.caches[cache_idx].active {
            self.caches[cache_idx].pagecnt_bias =
                self.caches[cache_idx].pagecnt_bias.saturating_sub(1);
        }

        self.fragments[idx].active = false;
        self.stats.total_free += 1;
        self.stats.fragments_active = self.stats.fragments_active.saturating_sub(1);

        Ok(())
    }

    /// Get an immutable reference to a fragment by index.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — index out of range
    /// * `NotFound` — fragment is not active
    pub fn get_fragment(&self, frag_idx: u32) -> Result<&PageFrag> {
        if frag_idx as usize >= MAX_FRAGMENTS {
            return Err(Error::InvalidArgument);
        }
        let idx = frag_idx as usize;
        if !self.fragments[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&self.fragments[idx])
    }

    /// Get an immutable reference to a cache by index.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — index out of range
    pub fn get_cache(&self, cache_idx: usize) -> Result<&PageFragCache> {
        if cache_idx >= MAX_CACHES {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.caches[cache_idx])
    }

    /// Return the number of active fragments.
    pub const fn active_fragment_count(&self) -> u32 {
        self.stats.fragments_active
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Find a free fragment slot.
    fn find_free_fragment(&self) -> Option<usize> {
        self.fragments.iter().position(|f| !f.active)
    }

    /// Refill a cache with a new backing page.
    fn refill_cache(&mut self, cache_idx: usize) -> Result<()> {
        if cache_idx >= MAX_CACHES {
            return Err(Error::InvalidArgument);
        }

        // Allocate a new page (bump allocator).
        let page_phys = self.next_page_phys;
        self.next_page_phys += u64::from(PAGE_SIZE);

        self.caches[cache_idx].refill(page_phys);
        self.stats.page_allocs += 1;
        Ok(())
    }
}

impl Default for PageFragPool {
    fn default() -> Self {
        Self::new(0)
    }
}

// -------------------------------------------------------------------
// Free-standing helpers
// -------------------------------------------------------------------

/// Align a size up to the fragment alignment boundary.
pub const fn frag_align_up(size: u16) -> u16 {
    (size + FRAG_ALIGN - 1) & !(FRAG_ALIGN - 1)
}

/// Validate a fragment allocation size.
///
/// Returns `Ok(aligned_size)` or `Err(InvalidArgument)`.
pub const fn validate_frag_size(size: u16) -> Result<u16> {
    if size < MIN_FRAG_SIZE || size > MAX_FRAG_SIZE {
        return Err(Error::InvalidArgument);
    }
    Ok(frag_align_up(size))
}
