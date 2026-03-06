// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! mlock internals — page locking and the unevictable LRU list.
//!
//! Implements the kernel side of `mlock(2)` / `munlock(2)` / `mlockall(2)`.
//! Locked pages are kept on the unevictable LRU list, bypassing the
//! page reclaimer entirely. This module handles VMA flag manipulation,
//! fault-in of pages, and LRU list management.
//!
//! # Subsystems
//!
//! - [`MlockFlags`] — VM_LOCKED and related VMA flags
//! - [`VmaInfo`] — lightweight VMA descriptor for mlock operations
//! - [`UnevictableLru`] — the unevictable (locked) page LRU list
//! - [`MlockManager`] — coordinates mlock/munlock operations
//! - [`MlockStats`] — statistics
//!
//! # Key Operations
//!
//! - `mlock_fixup` — set/clear VM_LOCKED on a VMA range
//! - `mlock_vma_pages_range` — fault in and lock pages
//! - `munlock_vma_pages_range` — unlock pages and move to active LRU
//!
//! Reference: Linux `mm/mlock.c`, `include/linux/mm.h`,
//! `include/uapi/linux/mman.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// VM_LOCKED flag bit.
const VM_LOCKED: u32 = 1 << 0;

/// VM_LOCKONFAULT — lock pages as they fault in, don't prefault.
const VM_LOCKONFAULT: u32 = 1 << 1;

/// Maximum VMAs tracked.
const MAX_VMAS: usize = 256;

/// Maximum pages on the unevictable LRU.
const MAX_UNEVICTABLE: usize = 8192;

/// Maximum pages to fault-in per mlock call.
const MAX_FAULTIN_BATCH: usize = 1024;

/// RLIMIT_MEMLOCK default in pages (64 MiB / 4 KiB).
const DEFAULT_MEMLOCK_LIMIT: u64 = 16384;

// -------------------------------------------------------------------
// MlockFlags
// -------------------------------------------------------------------

/// mlock-related flags for a VMA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MlockFlags(u32);

impl MlockFlags {
    /// No mlock flags set.
    pub const NONE: Self = Self(0);

    /// VM_LOCKED — pages are locked in memory.
    pub const LOCKED: Self = Self(VM_LOCKED);

    /// VM_LOCKONFAULT — lock on fault, don't prefault.
    pub const LOCKONFAULT: Self = Self(VM_LOCKONFAULT);

    /// Both locked and lock-on-fault.
    pub const LOCKED_ONFAULT: Self = Self(VM_LOCKED | VM_LOCKONFAULT);

    /// Creates from raw bits.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits & (VM_LOCKED | VM_LOCKONFAULT))
    }

    /// Returns raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns whether VM_LOCKED is set.
    pub const fn is_locked(self) -> bool {
        self.0 & VM_LOCKED != 0
    }

    /// Returns whether VM_LOCKONFAULT is set.
    pub const fn is_lockonfault(self) -> bool {
        self.0 & VM_LOCKONFAULT != 0
    }
}

// -------------------------------------------------------------------
// VmaInfo
// -------------------------------------------------------------------

/// Lightweight VMA descriptor for mlock operations.
#[derive(Debug, Clone, Copy)]
pub struct VmaInfo {
    /// VMA start address.
    pub start: u64,
    /// VMA end address (exclusive).
    pub end: u64,
    /// mlock flags.
    pub mlock_flags: MlockFlags,
    /// Protection flags (rwx).
    pub prot: u32,
    /// Number of present pages in this VMA.
    pub nr_present: u64,
    /// Number of locked pages.
    pub nr_locked: u64,
    /// Address space ID (mm_id).
    pub mm_id: u32,
    /// Whether this VMA is active.
    pub active: bool,
}

impl VmaInfo {
    /// Creates a new VMA info.
    pub const fn new(start: u64, end: u64, mm_id: u32) -> Self {
        Self {
            start,
            end,
            mlock_flags: MlockFlags::NONE,
            prot: 0,
            nr_present: 0,
            nr_locked: 0,
            mm_id,
            active: false,
        }
    }

    /// Returns the VMA size in bytes.
    pub const fn size(&self) -> u64 {
        self.end - self.start
    }

    /// Returns the number of pages in this VMA.
    pub const fn nr_pages(&self) -> u64 {
        (self.end - self.start) / PAGE_SIZE
    }

    /// Returns whether this VMA is locked.
    pub const fn is_locked(&self) -> bool {
        self.mlock_flags.is_locked()
    }
}

impl Default for VmaInfo {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

// -------------------------------------------------------------------
// UnevictableLru
// -------------------------------------------------------------------

/// The unevictable (locked) page list.
///
/// Pages on this list are never reclaimed by kswapd or direct reclaim.
/// They are moved here when locked via mlock and moved back to the
/// active LRU when unlocked.
pub struct UnevictableLru {
    /// PFNs of pages on the unevictable list.
    pages: [u64; MAX_UNEVICTABLE],
    /// Number of pages on the list.
    count: usize,
}

impl UnevictableLru {
    /// Creates a new empty unevictable LRU.
    pub const fn new() -> Self {
        Self {
            pages: [0; MAX_UNEVICTABLE],
            count: 0,
        }
    }

    /// Adds a page to the unevictable list.
    pub fn add(&mut self, pfn: u64) -> Result<()> {
        if self.count >= MAX_UNEVICTABLE {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicates
        for i in 0..self.count {
            if self.pages[i] == pfn {
                return Ok(()); // Already on the list
            }
        }
        self.pages[self.count] = pfn;
        self.count += 1;
        Ok(())
    }

    /// Removes a page from the unevictable list.
    pub fn remove(&mut self, pfn: u64) -> Result<()> {
        for i in 0..self.count {
            if self.pages[i] == pfn {
                if i < self.count - 1 {
                    self.pages[i] = self.pages[self.count - 1];
                }
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns whether a page is on the unevictable list.
    pub fn contains(&self, pfn: u64) -> bool {
        for i in 0..self.count {
            if self.pages[i] == pfn {
                return true;
            }
        }
        false
    }

    /// Returns the number of pages on the list.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Clears all pages from the list (e.g., on munlockall).
    pub fn clear(&mut self) {
        self.count = 0;
    }
}

impl Default for UnevictableLru {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MlockStats
// -------------------------------------------------------------------

/// mlock statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct MlockStats {
    /// Total mlock calls.
    pub mlock_calls: u64,
    /// Total munlock calls.
    pub munlock_calls: u64,
    /// Total pages locked.
    pub pages_locked: u64,
    /// Total pages unlocked.
    pub pages_unlocked: u64,
    /// Total pages faulted in for mlock.
    pub pages_faulted: u64,
    /// mlock calls that failed (limit exceeded).
    pub mlock_failures: u64,
}

impl MlockStats {
    /// Creates new zeroed statistics.
    pub const fn new() -> Self {
        Self {
            mlock_calls: 0,
            munlock_calls: 0,
            pages_locked: 0,
            pages_unlocked: 0,
            pages_faulted: 0,
            mlock_failures: 0,
        }
    }
}

// -------------------------------------------------------------------
// MlockManager
// -------------------------------------------------------------------

/// Coordinates mlock/munlock operations across VMAs and the
/// unevictable LRU.
pub struct MlockManager {
    /// Tracked VMAs.
    vmas: [VmaInfo; MAX_VMAS],
    /// Number of active VMAs.
    vma_count: usize,
    /// The unevictable page list.
    unevictable: UnevictableLru,
    /// Per-process locked page limit (RLIMIT_MEMLOCK) in pages.
    memlock_limit: u64,
    /// Current total locked pages across all VMAs.
    total_locked: u64,
    /// Statistics.
    stats: MlockStats,
}

impl MlockManager {
    /// Creates a new mlock manager.
    pub const fn new() -> Self {
        Self {
            vmas: [const { VmaInfo::new(0, 0, 0) }; MAX_VMAS],
            vma_count: 0,
            unevictable: UnevictableLru::new(),
            memlock_limit: DEFAULT_MEMLOCK_LIMIT,
            total_locked: 0,
            stats: MlockStats::new(),
        }
    }

    /// Sets the RLIMIT_MEMLOCK (in pages).
    pub fn set_memlock_limit(&mut self, limit: u64) {
        self.memlock_limit = limit;
    }

    /// Registers a VMA for tracking.
    pub fn register_vma(&mut self, vma: VmaInfo) -> Result<usize> {
        if self.vma_count >= MAX_VMAS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.vma_count;
        self.vmas[idx] = vma;
        self.vmas[idx].active = true;
        self.vma_count += 1;
        Ok(idx)
    }

    /// Unregisters a VMA by index.
    pub fn unregister_vma(&mut self, idx: usize) -> Result<()> {
        if idx >= self.vma_count {
            return Err(Error::InvalidArgument);
        }
        // Unlock any locked pages first
        if self.vmas[idx].is_locked() {
            let nr = self.vmas[idx].nr_locked;
            self.total_locked = self.total_locked.saturating_sub(nr);
        }
        if idx < self.vma_count - 1 {
            self.vmas[idx] = self.vmas[self.vma_count - 1];
        }
        self.vma_count -= 1;
        Ok(())
    }

    /// Sets VM_LOCKED on a VMA (mlock_fixup).
    ///
    /// Checks RLIMIT_MEMLOCK before locking.
    pub fn mlock_fixup(&mut self, vma_idx: usize, flags: MlockFlags) -> Result<()> {
        if vma_idx >= self.vma_count {
            return Err(Error::InvalidArgument);
        }

        let nr_pages = self.vmas[vma_idx].nr_pages();

        if flags.is_locked() && !self.vmas[vma_idx].is_locked() {
            // Check limit
            if self.total_locked + nr_pages > self.memlock_limit {
                self.stats.mlock_failures += 1;
                return Err(Error::OutOfMemory);
            }
        }

        let was_locked = self.vmas[vma_idx].is_locked();
        self.vmas[vma_idx].mlock_flags = flags;

        if flags.is_locked() && !was_locked {
            self.total_locked += nr_pages;
            self.vmas[vma_idx].nr_locked = nr_pages;
            self.stats.mlock_calls += 1;
        } else if !flags.is_locked() && was_locked {
            let locked = self.vmas[vma_idx].nr_locked;
            self.total_locked = self.total_locked.saturating_sub(locked);
            self.vmas[vma_idx].nr_locked = 0;
            self.stats.munlock_calls += 1;
        }

        Ok(())
    }

    /// Faults in and locks pages in a VMA range.
    ///
    /// `pfns` is the array of PFNs to lock. Only present pages
    /// (non-zero PFN) are added to the unevictable list.
    pub fn mlock_vma_pages_range(&mut self, vma_idx: usize, pfns: &[u64]) -> Result<usize> {
        if vma_idx >= self.vma_count {
            return Err(Error::InvalidArgument);
        }
        if !self.vmas[vma_idx].is_locked() {
            return Err(Error::InvalidArgument);
        }

        let mut locked = 0;
        let limit = pfns.len().min(MAX_FAULTIN_BATCH);

        for pfn in pfns.iter().take(limit) {
            if *pfn == 0 {
                continue; // Not present
            }
            if self.unevictable.add(*pfn).is_ok() {
                locked += 1;
            }
        }

        self.stats.pages_locked += locked as u64;
        self.stats.pages_faulted += locked as u64;
        Ok(locked)
    }

    /// Unlocks pages in a VMA range and moves them to the active LRU.
    pub fn munlock_vma_pages_range(&mut self, vma_idx: usize, pfns: &[u64]) -> Result<usize> {
        if vma_idx >= self.vma_count {
            return Err(Error::InvalidArgument);
        }

        let mut unlocked = 0;
        for pfn in pfns {
            if *pfn == 0 {
                continue;
            }
            if self.unevictable.remove(*pfn).is_ok() {
                unlocked += 1;
            }
        }

        self.stats.pages_unlocked += unlocked as u64;
        Ok(unlocked)
    }

    /// Returns the current number of locked pages.
    pub const fn total_locked(&self) -> u64 {
        self.total_locked
    }

    /// Returns the number of pages on the unevictable LRU.
    pub const fn unevictable_count(&self) -> usize {
        self.unevictable.count()
    }

    /// Returns a reference to the statistics.
    pub const fn stats(&self) -> &MlockStats {
        &self.stats
    }

    /// Returns the number of tracked VMAs.
    pub const fn vma_count(&self) -> usize {
        self.vma_count
    }

    /// Returns the memlock limit.
    pub const fn memlock_limit(&self) -> u64 {
        self.memlock_limit
    }
}

impl Default for MlockManager {
    fn default() -> Self {
        Self::new()
    }
}
