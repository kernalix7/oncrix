// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Centralized page flag management with compound page awareness.
//!
//! Every physical page frame in the system has an associated set of
//! flags that track its state: whether it is locked, dirty, on an LRU
//! list, part of the slab allocator, a compound (huge) page head or
//! tail, and so on. This module provides a unified API for querying
//! and manipulating these flags.
//!
//! # Design
//!
//! Page flags are stored in a per-PFN table (`PageFlagTable`) as `u64`
//! bitmasks. The module provides both raw flag operations and
//! semantic wrappers for common patterns (e.g., lock/unlock with
//! contention tracking, dirty/writeback interlock).
//!
//! For compound pages (2 MiB / 1 GiB huge pages), the HEAD flag is
//! set on the first PFN and TAIL on all subsequent PFNs. The
//! `compound_head()` function follows TAIL pages back to their head.
//!
//! # Flags
//!
//! 24 flags are defined, matching the Linux `page-flags.h` set:
//! LOCKED, REFERENCED, UPTODATE, DIRTY, LRU, ACTIVE, SLAB,
//! OWNER_PRIV, ARCH_1, RESERVED, PRIVATE, PRIVATE2, WRITEBACK,
//! HEAD, TAIL, COMPOUND, RECLAIM, SWAPBACKED, UNEVICTABLE,
//! MLOCKED, HWPOISON, IDLE, YOUNG, REPORTED.
//!
//! # Subsystems
//!
//! - [`PageFlags`] — bitflag constants and combinators
//! - [`PageFlagTable`] — per-PFN flag storage (8192 entries)
//! - [`CompoundInfo`] — compound page metadata
//! - [`PageFlagStats`] — flag operation statistics
//!
//! Reference: Linux `include/linux/page-flags.h`,
//! `mm/page_alloc.c`, `include/linux/mm.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of page frames tracked.
const MAX_PAGES: usize = 8192;

/// Number of PFNs in a 2 MiB compound page (512 * 4 KiB).
const COMPOUND_2M_PAGES: u64 = 512;

/// Number of PFNs in a 1 GiB compound page (262144 * 4 KiB).
const _COMPOUND_1G_PAGES: u64 = 262144;

/// Invalid PFN sentinel.
const INVALID_PFN: u64 = u64::MAX;

// -------------------------------------------------------------------
// PageFlags
// -------------------------------------------------------------------

/// Page state flags stored as a `u64` bitmask.
///
/// Each flag occupies one bit. Flags can be combined with bitwise OR
/// and tested with bitwise AND.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PageFlags(u64);

impl PageFlags {
    /// Page is locked for exclusive access.
    pub const LOCKED: Self = Self(1 << 0);

    /// Page has been accessed/referenced since last scan.
    pub const REFERENCED: Self = Self(1 << 1);

    /// Page contents are up-to-date with backing store.
    pub const UPTODATE: Self = Self(1 << 2);

    /// Page has been modified and needs writeback.
    pub const DIRTY: Self = Self(1 << 3);

    /// Page is on an LRU list.
    pub const LRU: Self = Self(1 << 4);

    /// Page is on the active LRU list.
    pub const ACTIVE: Self = Self(1 << 5);

    /// Page is owned by the slab allocator.
    pub const SLAB: Self = Self(1 << 6);

    /// Owner-private flag (filesystem-specific).
    pub const OWNER_PRIV: Self = Self(1 << 7);

    /// Architecture-specific flag 1.
    pub const ARCH_1: Self = Self(1 << 8);

    /// Page is reserved (not available for allocation).
    pub const RESERVED: Self = Self(1 << 9);

    /// Page has private data (e.g., buffer_head).
    pub const PRIVATE: Self = Self(1 << 10);

    /// Page has secondary private data.
    pub const PRIVATE2: Self = Self(1 << 11);

    /// Page is being written back to storage.
    pub const WRITEBACK: Self = Self(1 << 12);

    /// Page is the head of a compound page.
    pub const HEAD: Self = Self(1 << 13);

    /// Page is a tail page of a compound page.
    pub const TAIL: Self = Self(1 << 14);

    /// Page is part of a compound page (HEAD | TAIL).
    pub const COMPOUND: Self = Self(1 << 15);

    /// Page is a candidate for reclaim.
    pub const RECLAIM: Self = Self(1 << 16);

    /// Page is swap-backed (anonymous memory).
    pub const SWAPBACKED: Self = Self(1 << 17);

    /// Page is unevictable (mlock, ramfs, etc.).
    pub const UNEVICTABLE: Self = Self(1 << 18);

    /// Page is locked in memory via mlock.
    pub const MLOCKED: Self = Self(1 << 19);

    /// Page has a hardware-detected memory error.
    pub const HWPOISON: Self = Self(1 << 20);

    /// Page has been idle (no access) since last check.
    pub const IDLE: Self = Self(1 << 21);

    /// Page has been recently accessed (young generation).
    pub const YOUNG: Self = Self(1 << 22);

    /// Page has been reported to the hypervisor (free page reporting).
    pub const REPORTED: Self = Self(1 << 23);

    /// No flags set.
    pub const NONE: Self = Self(0);

    /// Create flags from a raw `u64` value.
    pub const fn from_raw(v: u64) -> Self {
        Self(v)
    }

    /// Return the raw `u64` representation.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Check whether `other` flags are all present in `self`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Combine two flag sets (bitwise OR).
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Remove specific flags (bitwise AND NOT).
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Intersection of two flag sets (bitwise AND).
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Whether no flags are set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Count the number of flags set.
    pub const fn count_set(self) -> u32 {
        self.0.count_ones()
    }

    /// Toggle specific flags (bitwise XOR).
    pub const fn toggle(self, other: Self) -> Self {
        Self(self.0 ^ other.0)
    }
}

// -------------------------------------------------------------------
// CompoundInfo
// -------------------------------------------------------------------

/// Metadata for a compound (huge) page.
///
/// Stored separately from the per-page flags to avoid bloating the
/// flag table. Only head pages have compound info.
#[derive(Debug, Clone, Copy)]
pub struct CompoundInfo {
    /// Head PFN of the compound page.
    pub head_pfn: u64,
    /// Number of pages in the compound page (2^order).
    pub nr_pages: u64,
    /// Compound page order (log2 of nr_pages).
    pub order: u8,
    /// Destructor type (0 = free, 1 = hugetlb, etc.).
    pub dtor_type: u8,
    /// Reference count for the compound page as a whole.
    pub compound_ref: u32,
    /// Whether this info slot is in use.
    pub active: bool,
}

impl CompoundInfo {
    /// Create an empty compound info.
    const fn empty() -> Self {
        Self {
            head_pfn: INVALID_PFN,
            nr_pages: 0,
            order: 0,
            dtor_type: 0,
            compound_ref: 0,
            active: false,
        }
    }

    /// End PFN (exclusive) of this compound page.
    pub const fn end_pfn(&self) -> u64 {
        self.head_pfn + self.nr_pages
    }

    /// Whether a PFN is part of this compound page.
    pub const fn contains_pfn(&self, pfn: u64) -> bool {
        pfn >= self.head_pfn && pfn < self.head_pfn + self.nr_pages
    }
}

// -------------------------------------------------------------------
// PageFlagStats
// -------------------------------------------------------------------

/// Page flag operation statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct PageFlagStats {
    /// Total number of flag set operations.
    pub total_set: u64,
    /// Total number of flag clear operations.
    pub total_cleared: u64,
    /// Number of lock contention events (trylock failures).
    pub lock_contentions: u64,
    /// Number of successful lock acquisitions.
    pub lock_acquisitions: u64,
    /// Number of dirty flag transitions (clean → dirty).
    pub dirty_transitions: u64,
    /// Number of writeback starts.
    pub writeback_starts: u64,
    /// Number of compound page setups.
    pub compound_setups: u64,
    /// Number of compound page teardowns.
    pub compound_teardowns: u64,
}

impl PageFlagStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_set: 0,
            total_cleared: 0,
            lock_contentions: 0,
            lock_acquisitions: 0,
            dirty_transitions: 0,
            writeback_starts: 0,
            compound_setups: 0,
            compound_teardowns: 0,
        }
    }
}

// -------------------------------------------------------------------
// PageFlagTable
// -------------------------------------------------------------------

/// Maximum number of compound page entries tracked.
const MAX_COMPOUND_ENTRIES: usize = 64;

/// Per-PFN page flag storage.
///
/// Stores flags for up to `MAX_PAGES` page frames, plus compound
/// page metadata for huge pages.
pub struct PageFlagTable {
    /// Flags for each PFN.
    flags: [PageFlags; MAX_PAGES],
    /// Compound page metadata.
    compounds: [CompoundInfo; MAX_COMPOUND_ENTRIES],
    /// Number of active compound entries.
    nr_compounds: usize,
    /// Operation statistics.
    stats: PageFlagStats,
    /// Whether the table has been initialized.
    initialized: bool,
}

impl PageFlagTable {
    /// Create a new uninitialized flag table.
    pub fn new() -> Self {
        Self {
            flags: [const { PageFlags::NONE }; MAX_PAGES],
            compounds: [const { CompoundInfo::empty() }; MAX_COMPOUND_ENTRIES],
            nr_compounds: 0,
            stats: PageFlagStats::new(),
            initialized: false,
        }
    }

    /// Initialize the flag table.
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        self.initialized = true;
        Ok(())
    }

    /// Whether the table is initialized.
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Current statistics.
    pub const fn stats(&self) -> &PageFlagStats {
        &self.stats
    }

    /// Get the flags for a PFN.
    pub fn get_flags(&self, pfn: u64) -> Result<PageFlags> {
        let idx = pfn as usize;
        if idx >= MAX_PAGES {
            return Err(Error::InvalidArgument);
        }
        Ok(self.flags[idx])
    }

    /// Set specific flags on a PFN (OR operation).
    pub fn set_page_flag(&mut self, pfn: u64, flag: PageFlags) -> Result<()> {
        let idx = pfn as usize;
        if idx >= MAX_PAGES {
            return Err(Error::InvalidArgument);
        }
        self.flags[idx] = self.flags[idx].union(flag);
        self.stats.total_set += 1;
        Ok(())
    }

    /// Clear specific flags on a PFN (AND NOT operation).
    pub fn clear_page_flag(&mut self, pfn: u64, flag: PageFlags) -> Result<()> {
        let idx = pfn as usize;
        if idx >= MAX_PAGES {
            return Err(Error::InvalidArgument);
        }
        self.flags[idx] = self.flags[idx].difference(flag);
        self.stats.total_cleared += 1;
        Ok(())
    }

    /// Test whether specific flags are set on a PFN.
    pub fn test_page_flag(&self, pfn: u64, flag: PageFlags) -> Result<bool> {
        let idx = pfn as usize;
        if idx >= MAX_PAGES {
            return Err(Error::InvalidArgument);
        }
        Ok(self.flags[idx].contains(flag))
    }

    /// Replace all flags on a PFN.
    pub fn set_all_flags(&mut self, pfn: u64, flags: PageFlags) -> Result<()> {
        let idx = pfn as usize;
        if idx >= MAX_PAGES {
            return Err(Error::InvalidArgument);
        }
        self.flags[idx] = flags;
        self.stats.total_set += 1;
        Ok(())
    }

    /// Clear all flags on a PFN.
    pub fn clear_all_flags(&mut self, pfn: u64) -> Result<()> {
        let idx = pfn as usize;
        if idx >= MAX_PAGES {
            return Err(Error::InvalidArgument);
        }
        self.flags[idx] = PageFlags::NONE;
        self.stats.total_cleared += 1;
        Ok(())
    }

    // --- Locking ---

    /// Attempt to lock a page (set LOCKED flag).
    ///
    /// Returns `Ok(true)` if the lock was acquired, `Ok(false)` if
    /// the page was already locked (contention).
    pub fn trylock_page(&mut self, pfn: u64) -> Result<bool> {
        let idx = pfn as usize;
        if idx >= MAX_PAGES {
            return Err(Error::InvalidArgument);
        }
        if self.flags[idx].contains(PageFlags::LOCKED) {
            self.stats.lock_contentions += 1;
            return Ok(false);
        }
        self.flags[idx] = self.flags[idx].union(PageFlags::LOCKED);
        self.stats.lock_acquisitions += 1;
        Ok(true)
    }

    /// Set the LOCKED flag on a page.
    ///
    /// Returns `Err(Busy)` if already locked.
    pub fn set_page_locked(&mut self, pfn: u64) -> Result<()> {
        let idx = pfn as usize;
        if idx >= MAX_PAGES {
            return Err(Error::InvalidArgument);
        }
        if self.flags[idx].contains(PageFlags::LOCKED) {
            self.stats.lock_contentions += 1;
            return Err(Error::Busy);
        }
        self.flags[idx] = self.flags[idx].union(PageFlags::LOCKED);
        self.stats.lock_acquisitions += 1;
        Ok(())
    }

    /// Clear the LOCKED flag on a page.
    pub fn clear_page_locked(&mut self, pfn: u64) -> Result<()> {
        let idx = pfn as usize;
        if idx >= MAX_PAGES {
            return Err(Error::InvalidArgument);
        }
        self.flags[idx] = self.flags[idx].difference(PageFlags::LOCKED);
        Ok(())
    }

    // --- Dirty / Writeback ---

    /// Mark a page as dirty.
    ///
    /// Tracks the clean-to-dirty transition in statistics.
    pub fn set_page_dirty(&mut self, pfn: u64) -> Result<()> {
        let idx = pfn as usize;
        if idx >= MAX_PAGES {
            return Err(Error::InvalidArgument);
        }
        if !self.flags[idx].contains(PageFlags::DIRTY) {
            self.stats.dirty_transitions += 1;
        }
        self.flags[idx] = self.flags[idx].union(PageFlags::DIRTY);
        self.stats.total_set += 1;
        Ok(())
    }

    /// Clear the dirty flag for I/O submission.
    ///
    /// This sets the WRITEBACK flag while clearing DIRTY, ensuring
    /// the dirty/writeback interlock is maintained.
    pub fn clear_page_dirty_for_io(&mut self, pfn: u64) -> Result<()> {
        let idx = pfn as usize;
        if idx >= MAX_PAGES {
            return Err(Error::InvalidArgument);
        }
        if !self.flags[idx].contains(PageFlags::DIRTY) {
            return Ok(()); // not dirty, nothing to do
        }
        self.flags[idx] = self.flags[idx]
            .difference(PageFlags::DIRTY)
            .union(PageFlags::WRITEBACK);
        self.stats.writeback_starts += 1;
        self.stats.total_cleared += 1;
        self.stats.total_set += 1;
        Ok(())
    }

    /// Complete writeback: clear the WRITEBACK flag.
    pub fn end_page_writeback(&mut self, pfn: u64) -> Result<()> {
        let idx = pfn as usize;
        if idx >= MAX_PAGES {
            return Err(Error::InvalidArgument);
        }
        self.flags[idx] = self.flags[idx].difference(PageFlags::WRITEBACK);
        self.stats.total_cleared += 1;
        Ok(())
    }

    // --- Compound pages ---

    /// Set up a compound page starting at `head_pfn` with `order`.
    ///
    /// Marks the head PFN with HEAD | COMPOUND and all tail PFNs
    /// with TAIL | COMPOUND.
    pub fn setup_compound(&mut self, head_pfn: u64, order: u8) -> Result<()> {
        let nr_pages = 1u64 << order;
        let head_idx = head_pfn as usize;
        let end_idx = head_idx + nr_pages as usize;

        if end_idx > MAX_PAGES {
            return Err(Error::InvalidArgument);
        }
        if self.nr_compounds >= MAX_COMPOUND_ENTRIES {
            return Err(Error::OutOfMemory);
        }

        // Mark head page.
        self.flags[head_idx] = self.flags[head_idx]
            .union(PageFlags::HEAD)
            .union(PageFlags::COMPOUND);

        // Mark tail pages.
        for i in (head_idx + 1)..end_idx {
            self.flags[i] = self.flags[i]
                .union(PageFlags::TAIL)
                .union(PageFlags::COMPOUND);
        }

        // Record compound info.
        let slot = self.compounds.iter().position(|c| !c.active);
        let slot = match slot {
            Some(s) => s,
            None => return Err(Error::OutOfMemory),
        };

        self.compounds[slot] = CompoundInfo {
            head_pfn,
            nr_pages,
            order,
            dtor_type: 0,
            compound_ref: 1,
            active: true,
        };
        self.nr_compounds += 1;
        self.stats.compound_setups += 1;

        Ok(())
    }

    /// Tear down a compound page, clearing HEAD/TAIL/COMPOUND flags.
    pub fn destroy_compound(&mut self, head_pfn: u64) -> Result<()> {
        // Find the compound info.
        let pos = self
            .compounds
            .iter()
            .position(|c| c.active && c.head_pfn == head_pfn);
        let pos = match pos {
            Some(p) => p,
            None => return Err(Error::NotFound),
        };

        let info = self.compounds[pos];
        let head_idx = info.head_pfn as usize;
        let end_idx = head_idx + info.nr_pages as usize;

        if end_idx > MAX_PAGES {
            return Err(Error::InvalidArgument);
        }

        // Clear compound flags from all pages.
        let clear_mask = PageFlags::HEAD
            .union(PageFlags::TAIL)
            .union(PageFlags::COMPOUND);

        for i in head_idx..end_idx {
            self.flags[i] = self.flags[i].difference(clear_mask);
        }

        self.compounds[pos] = CompoundInfo::empty();
        self.nr_compounds = self.nr_compounds.saturating_sub(1);
        self.stats.compound_teardowns += 1;

        Ok(())
    }

    /// Get the head PFN for a given PFN.
    ///
    /// If the PFN is a tail page, returns the head PFN.
    /// If it is a head page or non-compound, returns itself.
    pub fn compound_head(&self, pfn: u64) -> u64 {
        let idx = pfn as usize;
        if idx >= MAX_PAGES {
            return pfn;
        }

        // Not a tail page: return self.
        if !self.flags[idx].contains(PageFlags::TAIL) {
            return pfn;
        }

        // Search compound entries for the one containing this PFN.
        for info in &self.compounds {
            if info.active && info.contains_pfn(pfn) {
                return info.head_pfn;
            }
        }

        // Fallback: walk backwards to find HEAD.
        let mut search = pfn;
        while search > 0 {
            search -= 1;
            let si = search as usize;
            if si >= MAX_PAGES {
                break;
            }
            if self.flags[si].contains(PageFlags::HEAD) {
                return search;
            }
            if !self.flags[si].contains(PageFlags::TAIL) {
                break;
            }
        }

        pfn
    }

    /// Get compound page order for a head PFN.
    pub fn compound_order(&self, head_pfn: u64) -> Result<u8> {
        for info in &self.compounds {
            if info.active && info.head_pfn == head_pfn {
                return Ok(info.order);
            }
        }
        Err(Error::NotFound)
    }

    /// Get the number of pages in a compound page.
    pub fn compound_nr_pages(&self, head_pfn: u64) -> Result<u64> {
        for info in &self.compounds {
            if info.active && info.head_pfn == head_pfn {
                return Ok(info.nr_pages);
            }
        }
        Err(Error::NotFound)
    }

    // --- Bulk operations ---

    /// Set a flag on a range of PFNs.
    pub fn set_range_flag(&mut self, start_pfn: u64, count: u64, flag: PageFlags) -> Result<u64> {
        let start = start_pfn as usize;
        let end = start + count as usize;
        if end > MAX_PAGES {
            return Err(Error::InvalidArgument);
        }
        let mut set_count: u64 = 0;
        for i in start..end {
            self.flags[i] = self.flags[i].union(flag);
            set_count += 1;
        }
        self.stats.total_set += set_count;
        Ok(set_count)
    }

    /// Clear a flag on a range of PFNs.
    pub fn clear_range_flag(&mut self, start_pfn: u64, count: u64, flag: PageFlags) -> Result<u64> {
        let start = start_pfn as usize;
        let end = start + count as usize;
        if end > MAX_PAGES {
            return Err(Error::InvalidArgument);
        }
        let mut cleared: u64 = 0;
        for i in start..end {
            self.flags[i] = self.flags[i].difference(flag);
            cleared += 1;
        }
        self.stats.total_cleared += cleared;
        Ok(cleared)
    }

    /// Count pages with a specific flag set in a range.
    pub fn count_flag_in_range(&self, start_pfn: u64, count: u64, flag: PageFlags) -> Result<u64> {
        let start = start_pfn as usize;
        let end = start + count as usize;
        if end > MAX_PAGES {
            return Err(Error::InvalidArgument);
        }
        let mut found: u64 = 0;
        for i in start..end {
            if self.flags[i].contains(flag) {
                found += 1;
            }
        }
        Ok(found)
    }

    /// Number of compound pages currently tracked.
    pub const fn nr_compounds(&self) -> usize {
        self.nr_compounds
    }

    /// Total pages across all compound pages.
    pub fn total_compound_pages(&self) -> u64 {
        let mut total: u64 = 0;
        for info in &self.compounds {
            if info.active {
                total += info.nr_pages;
            }
        }
        total
    }

    /// Total compound pages in 2 MiB units.
    pub fn compound_2m_count(&self) -> u64 {
        let mut count: u64 = 0;
        for info in &self.compounds {
            if info.active && info.nr_pages == COMPOUND_2M_PAGES {
                count += 1;
            }
        }
        count
    }
}

impl Default for PageFlagTable {
    fn default() -> Self {
        Self::new()
    }
}
