// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Shmem/tmpfs swap-out support.
//!
//! `tmpfs` (and `shmem` in general) keeps data in anonymous pages
//! backed by swap. Unlike a regular file system that writes dirty
//! pages to disk, tmpfs writes them to a swap device when memory
//! pressure is high. This module implements:
//!
//! - **Swap-out**: selecting shmem pages for eviction, writing them
//!   to swap slots, and replacing the page-cache entry with a swap
//!   entry.
//! - **Swap-in**: on fault, reading the page back from swap and
//!   re-inserting it into the shmem page cache.
//! - **Swap accounting**: tracking how many swap slots each shmem
//!   inode consumes.
//!
//! # Architecture
//!
//! - [`ShmemSwapEntry`] — one cached page (or swap entry) for an
//!   inode+offset pair
//! - [`ShmemInode`] — per-inode metadata (page cache + swap slots)
//! - [`ShmemSwapTable`] — system-wide table of shmem inodes
//! - [`ShmemSwapSubsystem`] — top-level subsystem
//! - [`ShmemSwapStats`] — aggregate statistics
//!
//! Reference: Linux `mm/shmem.c` — `shmem_writepage()`,
//! `shmem_swapin_folio()`, `shmem_get_folio_gfp()`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of shmem inodes tracked.
const MAX_INODES: usize = 256;

/// Maximum number of page/swap entries per inode.
const MAX_ENTRIES_PER_INODE: usize = 256;

/// Maximum number of swap slots system-wide for shmem.
const MAX_SWAP_SLOTS: usize = 4096;

/// Swap slot value meaning "no slot".
const SWAP_NONE: u64 = 0;

/// Swap type identifier for shmem swap area.
const SHMEM_SWAP_TYPE: u8 = 2;

// -------------------------------------------------------------------
// ShmemEntryState
// -------------------------------------------------------------------

/// State of a single shmem page/swap entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShmemEntryState {
    /// No entry at this offset.
    #[default]
    Empty,
    /// Page is resident in memory.
    Resident,
    /// Page has been swapped out.
    SwappedOut,
    /// Page is being swapped in (fault in progress).
    SwappingIn,
    /// Page is being swapped out (writeback in progress).
    SwappingOut,
    /// Page was truncated (inode shrank).
    Truncated,
}

// -------------------------------------------------------------------
// ShmemSwapEntry
// -------------------------------------------------------------------

/// One entry in a shmem inode's page/swap cache.
///
/// At any given time, the entry is either backed by a resident page
/// (with a physical frame number) or by a swap slot.
#[derive(Debug, Clone, Copy)]
pub struct ShmemSwapEntry {
    /// Offset within the inode (in pages).
    pub pgoff: u64,
    /// Physical frame number (valid when state == Resident).
    pub pfn: u64,
    /// Swap slot offset (valid when state == SwappedOut).
    pub swap_offset: u64,
    /// Swap type identifier.
    pub swap_type: u8,
    /// Current state of this entry.
    pub state: ShmemEntryState,
    /// Whether this slot is in use.
    pub active: bool,
    /// Number of faults that loaded this page from swap.
    pub fault_count: u32,
    /// Number of times this page was written back to swap.
    pub writeback_count: u32,
}

impl ShmemSwapEntry {
    /// Create an empty entry.
    const fn empty() -> Self {
        Self {
            pgoff: 0,
            pfn: 0,
            swap_offset: SWAP_NONE,
            swap_type: 0,
            state: ShmemEntryState::Empty,
            active: false,
            fault_count: 0,
            writeback_count: 0,
        }
    }

    /// Whether the page is in memory.
    pub fn is_resident(&self) -> bool {
        self.state == ShmemEntryState::Resident
    }

    /// Whether the page is on swap.
    pub fn is_swapped(&self) -> bool {
        self.state == ShmemEntryState::SwappedOut
    }

    /// Whether this entry is in a transitional state.
    pub fn is_in_transit(&self) -> bool {
        matches!(
            self.state,
            ShmemEntryState::SwappingIn | ShmemEntryState::SwappingOut
        )
    }

    /// Mark as swapped out (swap-out completion).
    pub fn mark_swapped(&mut self, swap_offset: u64, swap_type: u8) {
        self.swap_offset = swap_offset;
        self.swap_type = swap_type;
        self.pfn = 0;
        self.state = ShmemEntryState::SwappedOut;
        self.writeback_count = self.writeback_count.saturating_add(1);
    }

    /// Mark as resident (swap-in completion).
    pub fn mark_resident(&mut self, pfn: u64) {
        self.pfn = pfn;
        self.swap_offset = SWAP_NONE;
        self.state = ShmemEntryState::Resident;
        self.fault_count = self.fault_count.saturating_add(1);
    }
}

impl Default for ShmemSwapEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// ShmemInode
// -------------------------------------------------------------------

/// Per-inode shmem metadata.
///
/// Tracks which pages are resident and which have been swapped out.
#[derive(Debug, Clone, Copy)]
pub struct ShmemInode {
    /// Inode number.
    pub ino: u64,
    /// Size of the file in pages.
    pub size_pages: u64,
    /// Page/swap entries.
    pub entries: [ShmemSwapEntry; MAX_ENTRIES_PER_INODE],
    /// Number of active entries.
    pub entry_count: u32,
    /// Number of currently resident pages.
    pub resident_pages: u32,
    /// Number of pages currently on swap.
    pub swapped_pages: u32,
    /// Whether this inode slot is in use.
    pub active: bool,
    /// File mode (permissions).
    pub mode: u32,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
}

impl ShmemInode {
    /// Create an empty inode.
    const fn empty() -> Self {
        Self {
            ino: 0,
            size_pages: 0,
            entries: [const { ShmemSwapEntry::empty() }; MAX_ENTRIES_PER_INODE],
            entry_count: 0,
            resident_pages: 0,
            swapped_pages: 0,
            active: false,
            mode: 0,
            uid: 0,
            gid: 0,
        }
    }

    /// Find an entry by page offset.
    fn find_entry(&self, pgoff: u64) -> Option<usize> {
        self.entries
            .iter()
            .take(self.entry_count as usize)
            .position(|e| e.active && e.pgoff == pgoff)
    }

    /// Add or get a resident page at `pgoff`.
    pub fn add_page(&mut self, pgoff: u64, pfn: u64) -> Result<usize> {
        if let Some(idx) = self.find_entry(pgoff) {
            // Already exists — update if not resident.
            let entry = &mut self.entries[idx];
            if entry.is_resident() {
                return Err(Error::AlreadyExists);
            }
            if entry.is_swapped() {
                self.swapped_pages = self.swapped_pages.saturating_sub(1);
            }
            entry.mark_resident(pfn);
            self.resident_pages = self.resident_pages.saturating_add(1);
            return Ok(idx);
        }
        // New entry.
        if self.entry_count as usize >= MAX_ENTRIES_PER_INODE {
            return Err(Error::OutOfMemory);
        }
        let idx = self.entry_count as usize;
        self.entries[idx].pgoff = pgoff;
        self.entries[idx].pfn = pfn;
        self.entries[idx].state = ShmemEntryState::Resident;
        self.entries[idx].active = true;
        self.entry_count += 1;
        self.resident_pages = self.resident_pages.saturating_add(1);
        Ok(idx)
    }

    /// Initiate swap-out for a page at `pgoff`.
    pub fn start_swapout(&mut self, pgoff: u64) -> Result<u64> {
        let idx = self.find_entry(pgoff).ok_or(Error::NotFound)?;
        let entry = &mut self.entries[idx];
        if !entry.is_resident() {
            return Err(Error::InvalidArgument);
        }
        let pfn = entry.pfn;
        entry.state = ShmemEntryState::SwappingOut;
        Ok(pfn)
    }

    /// Complete swap-out for a page.
    pub fn complete_swapout(&mut self, pgoff: u64, swap_offset: u64, swap_type: u8) -> Result<()> {
        let idx = self.find_entry(pgoff).ok_or(Error::NotFound)?;
        let entry = &mut self.entries[idx];
        if entry.state != ShmemEntryState::SwappingOut {
            return Err(Error::InvalidArgument);
        }
        entry.mark_swapped(swap_offset, swap_type);
        self.resident_pages = self.resident_pages.saturating_sub(1);
        self.swapped_pages = self.swapped_pages.saturating_add(1);
        Ok(())
    }

    /// Initiate swap-in for a page at `pgoff`.
    pub fn start_swapin(&mut self, pgoff: u64) -> Result<(u64, u8)> {
        let idx = self.find_entry(pgoff).ok_or(Error::NotFound)?;
        let entry = &mut self.entries[idx];
        if !entry.is_swapped() {
            return Err(Error::InvalidArgument);
        }
        let slot = entry.swap_offset;
        let stype = entry.swap_type;
        entry.state = ShmemEntryState::SwappingIn;
        Ok((slot, stype))
    }

    /// Complete swap-in: page is now resident.
    pub fn complete_swapin(&mut self, pgoff: u64, pfn: u64) -> Result<()> {
        let idx = self.find_entry(pgoff).ok_or(Error::NotFound)?;
        let entry = &mut self.entries[idx];
        if entry.state != ShmemEntryState::SwappingIn {
            return Err(Error::InvalidArgument);
        }
        entry.mark_resident(pfn);
        self.swapped_pages = self.swapped_pages.saturating_sub(1);
        self.resident_pages = self.resident_pages.saturating_add(1);
        Ok(())
    }

    /// Truncate entries beyond `new_size_pages`.
    pub fn truncate(&mut self, new_size_pages: u64) -> u32 {
        let mut freed = 0u32;
        for i in 0..self.entry_count as usize {
            if self.entries[i].active && self.entries[i].pgoff >= new_size_pages {
                if self.entries[i].is_resident() {
                    self.resident_pages = self.resident_pages.saturating_sub(1);
                } else if self.entries[i].is_swapped() {
                    self.swapped_pages = self.swapped_pages.saturating_sub(1);
                }
                self.entries[i].state = ShmemEntryState::Truncated;
                self.entries[i].active = false;
                freed += 1;
            }
        }
        self.size_pages = new_size_pages;
        freed
    }

    /// Total pages (resident + swapped).
    pub fn total_pages(&self) -> u32 {
        self.resident_pages.saturating_add(self.swapped_pages)
    }
}

impl Default for ShmemInode {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// SwapSlot
// -------------------------------------------------------------------

/// A single swap slot used by shmem.
#[derive(Debug, Clone, Copy)]
pub struct SwapSlot {
    /// Swap offset (unique identifier within the swap area).
    pub offset: u64,
    /// Inode that owns this slot.
    pub ino: u64,
    /// Page offset within the inode.
    pub pgoff: u64,
    /// Whether this slot is in use.
    pub in_use: bool,
    /// Swap type.
    pub swap_type: u8,
}

impl SwapSlot {
    /// Create a free slot.
    const fn free(offset: u64) -> Self {
        Self {
            offset,
            ino: 0,
            pgoff: 0,
            in_use: false,
            swap_type: 0,
        }
    }
}

impl Default for SwapSlot {
    fn default() -> Self {
        Self::free(0)
    }
}

// -------------------------------------------------------------------
// ShmemSwapArea
// -------------------------------------------------------------------

/// Swap area reserved for shmem pages.
pub struct ShmemSwapArea {
    /// Swap slots.
    slots: [SwapSlot; MAX_SWAP_SLOTS],
    /// Number of free slots.
    free_count: usize,
    /// Total capacity.
    capacity: usize,
    /// Next slot to check (free-list scan hint).
    next_scan: usize,
}

impl ShmemSwapArea {
    /// Create a new swap area with all slots free.
    pub const fn new() -> Self {
        let mut area = Self {
            slots: [const { SwapSlot::free(0) }; MAX_SWAP_SLOTS],
            free_count: MAX_SWAP_SLOTS,
            capacity: MAX_SWAP_SLOTS,
            next_scan: 0,
        };
        let mut i = 0;
        while i < MAX_SWAP_SLOTS {
            area.slots[i].offset = i as u64;
            i += 1;
        }
        area
    }

    /// Allocate a swap slot for an inode page.
    pub fn alloc(&mut self, ino: u64, pgoff: u64) -> Result<u64> {
        if self.free_count == 0 {
            return Err(Error::OutOfMemory);
        }
        // Scan from next_scan for a free slot.
        let start = self.next_scan;
        for i in 0..self.capacity {
            let idx = (start + i) % self.capacity;
            if !self.slots[idx].in_use {
                self.slots[idx].in_use = true;
                self.slots[idx].ino = ino;
                self.slots[idx].pgoff = pgoff;
                self.slots[idx].swap_type = SHMEM_SWAP_TYPE;
                self.free_count -= 1;
                self.next_scan = (idx + 1) % self.capacity;
                return Ok(self.slots[idx].offset);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Free a swap slot.
    pub fn free(&mut self, offset: u64) -> Result<()> {
        let idx = offset as usize;
        if idx >= self.capacity {
            return Err(Error::InvalidArgument);
        }
        if !self.slots[idx].in_use {
            return Err(Error::NotFound);
        }
        self.slots[idx].in_use = false;
        self.slots[idx].ino = 0;
        self.slots[idx].pgoff = 0;
        self.free_count += 1;
        Ok(())
    }

    /// Number of free slots.
    pub fn free_count(&self) -> usize {
        self.free_count
    }

    /// Number of used slots.
    pub fn used_count(&self) -> usize {
        self.capacity - self.free_count
    }

    /// Total capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Usage fraction (0..100).
    pub fn usage_percent(&self) -> u64 {
        if self.capacity == 0 {
            return 0;
        }
        ((self.used_count() as u64) * 100) / (self.capacity as u64)
    }
}

impl Default for ShmemSwapArea {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// ShmemSwapTable
// -------------------------------------------------------------------

/// System-wide table of shmem inodes.
pub struct ShmemSwapTable {
    /// Inode entries.
    inodes: [ShmemInode; MAX_INODES],
    /// Number of active inodes.
    active_count: usize,
    /// Swap area.
    swap: ShmemSwapArea,
}

impl ShmemSwapTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            inodes: [const { ShmemInode::empty() }; MAX_INODES],
            active_count: 0,
            swap: ShmemSwapArea::new(),
        }
    }

    /// Register a new shmem inode.
    pub fn register_inode(
        &mut self,
        ino: u64,
        size_pages: u64,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<usize> {
        for inode in self.inodes.iter().take(self.active_count) {
            if inode.active && inode.ino == ino {
                return Err(Error::AlreadyExists);
            }
        }
        if self.active_count >= MAX_INODES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.active_count;
        self.inodes[idx].ino = ino;
        self.inodes[idx].size_pages = size_pages;
        self.inodes[idx].mode = mode;
        self.inodes[idx].uid = uid;
        self.inodes[idx].gid = gid;
        self.inodes[idx].active = true;
        self.active_count += 1;
        Ok(idx)
    }

    /// Unregister an inode.
    pub fn unregister_inode(&mut self, ino: u64) -> Result<()> {
        let pos = self
            .inodes
            .iter()
            .take(self.active_count)
            .position(|n| n.active && n.ino == ino)
            .ok_or(Error::NotFound)?;

        // Free any swap slots held by this inode.
        for i in 0..self.inodes[pos].entry_count as usize {
            let entry = &self.inodes[pos].entries[i];
            if entry.active && entry.is_swapped() {
                let _ = self.swap.free(entry.swap_offset);
            }
        }

        self.active_count -= 1;
        if pos < self.active_count {
            self.inodes[pos] = self.inodes[self.active_count];
        }
        self.inodes[self.active_count] = ShmemInode::empty();
        Ok(())
    }

    /// Find inode index by inode number.
    fn find_inode(&mut self, ino: u64) -> Result<usize> {
        self.inodes
            .iter()
            .take(self.active_count)
            .position(|n| n.active && n.ino == ino)
            .ok_or(Error::NotFound)
    }

    /// Add a resident page to an inode.
    pub fn add_page(&mut self, ino: u64, pgoff: u64, pfn: u64) -> Result<()> {
        let idx = self.find_inode(ino)?;
        self.inodes[idx].add_page(pgoff, pfn)?;
        Ok(())
    }

    /// Swap out a page from an inode.
    pub fn swap_out(&mut self, ino: u64, pgoff: u64) -> Result<SwapOutResult> {
        let idx = self.find_inode(ino)?;
        let pfn = self.inodes[idx].start_swapout(pgoff)?;
        let swap_offset = self.swap.alloc(ino, pgoff)?;
        self.inodes[idx].complete_swapout(pgoff, swap_offset, SHMEM_SWAP_TYPE)?;
        Ok(SwapOutResult {
            pfn,
            swap_offset,
            swap_type: SHMEM_SWAP_TYPE,
        })
    }

    /// Swap in a page for an inode.
    pub fn swap_in(&mut self, ino: u64, pgoff: u64, new_pfn: u64) -> Result<SwapInResult> {
        let idx = self.find_inode(ino)?;
        let (swap_offset, swap_type) = self.inodes[idx].start_swapin(pgoff)?;
        self.inodes[idx].complete_swapin(pgoff, new_pfn)?;
        self.swap.free(swap_offset)?;
        Ok(SwapInResult {
            swap_offset,
            swap_type,
            pfn: new_pfn,
        })
    }

    /// Get inode statistics.
    pub fn inode_info(&self, ino: u64) -> Result<ShmemInodeInfo> {
        let idx = self
            .inodes
            .iter()
            .take(self.active_count)
            .position(|n| n.active && n.ino == ino)
            .ok_or(Error::NotFound)?;
        let inode = &self.inodes[idx];
        Ok(ShmemInodeInfo {
            ino,
            size_pages: inode.size_pages,
            resident_pages: inode.resident_pages,
            swapped_pages: inode.swapped_pages,
            total_entries: inode.entry_count,
        })
    }

    /// Number of active inodes.
    pub fn active_count(&self) -> usize {
        self.active_count
    }

    /// Swap area reference.
    pub fn swap_area(&self) -> &ShmemSwapArea {
        &self.swap
    }
}

impl Default for ShmemSwapTable {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// SwapOutResult / SwapInResult
// -------------------------------------------------------------------

/// Result of a successful swap-out operation.
#[derive(Debug, Clone, Copy)]
pub struct SwapOutResult {
    /// PFN of the page that was swapped out (now free).
    pub pfn: u64,
    /// Swap slot where the data was written.
    pub swap_offset: u64,
    /// Swap type.
    pub swap_type: u8,
}

/// Result of a successful swap-in operation.
#[derive(Debug, Clone, Copy)]
pub struct SwapInResult {
    /// Swap slot that was freed.
    pub swap_offset: u64,
    /// Swap type.
    pub swap_type: u8,
    /// PFN where the page is now resident.
    pub pfn: u64,
}

// -------------------------------------------------------------------
// ShmemInodeInfo
// -------------------------------------------------------------------

/// Summary information about a shmem inode.
#[derive(Debug, Clone, Copy, Default)]
pub struct ShmemInodeInfo {
    /// Inode number.
    pub ino: u64,
    /// File size in pages.
    pub size_pages: u64,
    /// Resident pages.
    pub resident_pages: u32,
    /// Swapped pages.
    pub swapped_pages: u32,
    /// Total entries (active).
    pub total_entries: u32,
}

// -------------------------------------------------------------------
// ShmemSwapStats
// -------------------------------------------------------------------

/// Aggregate statistics for the shmem swap subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct ShmemSwapStats {
    /// Number of active inodes.
    pub active_inodes: u64,
    /// Total resident pages across all inodes.
    pub total_resident: u64,
    /// Total swapped pages across all inodes.
    pub total_swapped: u64,
    /// Swap area usage (used slots).
    pub swap_used: u64,
    /// Swap area capacity.
    pub swap_capacity: u64,
    /// Swap area usage percentage.
    pub swap_usage_percent: u64,
    /// Total swap-out operations.
    pub total_swapouts: u64,
    /// Total swap-in operations.
    pub total_swapins: u64,
}

// -------------------------------------------------------------------
// ShmemSwapSubsystem
// -------------------------------------------------------------------

/// Top-level shmem/tmpfs swap subsystem.
pub struct ShmemSwapSubsystem {
    /// The underlying table.
    table: ShmemSwapTable,
    /// Whether the subsystem has been initialised.
    initialised: bool,
    /// Total swap-out operations since init.
    total_swapouts: u64,
    /// Total swap-in operations since init.
    total_swapins: u64,
}

impl ShmemSwapSubsystem {
    /// Create an uninitialised subsystem.
    pub const fn new() -> Self {
        Self {
            table: ShmemSwapTable::new(),
            initialised: false,
            total_swapouts: 0,
            total_swapins: 0,
        }
    }

    /// Initialise the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.initialised = true;
        Ok(())
    }

    /// Register a shmem inode.
    pub fn register_inode(
        &mut self,
        ino: u64,
        size_pages: u64,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<usize> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        self.table.register_inode(ino, size_pages, mode, uid, gid)
    }

    /// Unregister a shmem inode.
    pub fn unregister_inode(&mut self, ino: u64) -> Result<()> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        self.table.unregister_inode(ino)
    }

    /// Add a resident page.
    pub fn add_page(&mut self, ino: u64, pgoff: u64, pfn: u64) -> Result<()> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        self.table.add_page(ino, pgoff, pfn)
    }

    /// Swap out a page.
    pub fn swap_out(&mut self, ino: u64, pgoff: u64) -> Result<SwapOutResult> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        let result = self.table.swap_out(ino, pgoff)?;
        self.total_swapouts = self.total_swapouts.saturating_add(1);
        Ok(result)
    }

    /// Swap in a page.
    pub fn swap_in(&mut self, ino: u64, pgoff: u64, new_pfn: u64) -> Result<SwapInResult> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        let result = self.table.swap_in(ino, pgoff, new_pfn)?;
        self.total_swapins = self.total_swapins.saturating_add(1);
        Ok(result)
    }

    /// Get inode info.
    pub fn inode_info(&self, ino: u64) -> Result<ShmemInodeInfo> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        self.table.inode_info(ino)
    }

    /// Collect aggregate statistics.
    pub fn stats(&self) -> ShmemSwapStats {
        let mut s = ShmemSwapStats {
            active_inodes: self.table.active_count() as u64,
            swap_used: self.table.swap_area().used_count() as u64,
            swap_capacity: self.table.swap_area().capacity() as u64,
            swap_usage_percent: self.table.swap_area().usage_percent(),
            total_swapouts: self.total_swapouts,
            total_swapins: self.total_swapins,
            ..ShmemSwapStats::default()
        };
        for inode in self.table.inodes.iter().take(self.table.active_count) {
            if !inode.active {
                continue;
            }
            s.total_resident = s.total_resident.saturating_add(inode.resident_pages as u64);
            s.total_swapped = s.total_swapped.saturating_add(inode.swapped_pages as u64);
        }
        s
    }

    /// Whether the subsystem is initialised.
    pub fn is_initialised(&self) -> bool {
        self.initialised
    }
}

impl Default for ShmemSwapSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Reclaim helpers
// -------------------------------------------------------------------

/// Select shmem pages for reclaim based on LRU-like heuristics.
///
/// Scans the inode table and selects up to `count` resident pages
/// with the lowest fault counts (cold pages) for swap-out.
pub fn select_for_reclaim(
    table: &ShmemSwapTable,
    count: usize,
) -> ([ShmemReclaimCandidate; 64], usize) {
    let mut candidates = [ShmemReclaimCandidate::empty(); 64];
    let mut found = 0usize;
    let max = if count > 64 { 64 } else { count };

    for inode in table.inodes.iter().take(table.active_count) {
        if !inode.active {
            continue;
        }
        for entry in inode.entries.iter().take(inode.entry_count as usize) {
            if !entry.active || !entry.is_resident() {
                continue;
            }
            if found < max {
                candidates[found] = ShmemReclaimCandidate {
                    ino: inode.ino,
                    pgoff: entry.pgoff,
                    pfn: entry.pfn,
                    fault_count: entry.fault_count,
                    valid: true,
                };
                found += 1;
            } else {
                // Replace the candidate with the highest fault count
                // (keep the coldest pages).
                let mut worst_idx = 0;
                let mut worst_faults = 0u32;
                for (i, c) in candidates.iter().enumerate().take(max) {
                    if c.fault_count > worst_faults {
                        worst_faults = c.fault_count;
                        worst_idx = i;
                    }
                }
                if entry.fault_count < worst_faults {
                    candidates[worst_idx] = ShmemReclaimCandidate {
                        ino: inode.ino,
                        pgoff: entry.pgoff,
                        pfn: entry.pfn,
                        fault_count: entry.fault_count,
                        valid: true,
                    };
                }
            }
        }
    }
    (candidates, found)
}

/// Candidate page for shmem reclaim.
#[derive(Debug, Clone, Copy)]
pub struct ShmemReclaimCandidate {
    /// Inode number.
    pub ino: u64,
    /// Page offset.
    pub pgoff: u64,
    /// Physical frame number.
    pub pfn: u64,
    /// Number of faults (lower = colder = better candidate).
    pub fault_count: u32,
    /// Whether this candidate is valid.
    pub valid: bool,
}

impl ShmemReclaimCandidate {
    /// Create an empty candidate.
    const fn empty() -> Self {
        Self {
            ino: 0,
            pgoff: 0,
            pfn: 0,
            fault_count: 0,
            valid: false,
        }
    }
}

impl Default for ShmemReclaimCandidate {
    fn default() -> Self {
        Self::empty()
    }
}
