// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared memory (shmem/tmpfs) backing store implementation.
//!
//! Provides the in-memory filesystem backing for `tmpfs`, POSIX
//! shared memory (`shm_open`), and anonymous shared mappings. Pages
//! are allocated on demand (fault-driven) and can be swapped out
//! under memory pressure.
//!
//! # Subsystems
//!
//! - [`ShmemPageState`] — state of a page slot (empty / present / swapped)
//! - [`ShmemInode`] — inode with page array and swap tracking
//! - [`ShmemFs`] — filesystem-level manager for shmem inodes
//! - [`ShmemStats`] — allocation and swap statistics
//!
//! # Key Operations
//!
//! - `shmem_getpage` — allocate page on fault (or bring back from swap)
//! - `shmem_writepage` — swap out a page under reclaim
//! - `shmem_truncate` — shrink file, free or swap-invalidate pages
//! - `shmem_fallocate` — hole-punch or preallocate pages
//!
//! Reference: Linux `mm/shmem.c`, `include/linux/shmem_fs.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum pages per shmem inode.
const MAX_PAGES_PER_INODE: usize = 4096;

/// Maximum shmem inodes managed by the filesystem.
const MAX_INODES: usize = 256;

/// Invalid swap entry sentinel.
const SWAP_ENTRY_NONE: u64 = u64::MAX;

/// Invalid PFN sentinel.
const PFN_NONE: u64 = u64::MAX;

// -------------------------------------------------------------------
// ShmemPageState
// -------------------------------------------------------------------

/// State of a single page slot in a shmem inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShmemPageState {
    /// Slot is empty — no data has been written here.
    Empty,
    /// Page is present in memory at the given PFN.
    Present(u64),
    /// Page has been swapped out to the given swap entry.
    Swapped(u64),
}

impl ShmemPageState {
    /// Returns true if the slot has data (present or swapped).
    pub const fn has_data(&self) -> bool {
        !matches!(self, Self::Empty)
    }

    /// Returns the PFN if present, None otherwise.
    pub const fn pfn(&self) -> Option<u64> {
        match self {
            Self::Present(pfn) => Some(*pfn),
            _ => None,
        }
    }

    /// Returns the swap entry if swapped, None otherwise.
    pub const fn swap_entry(&self) -> Option<u64> {
        match self {
            Self::Swapped(entry) => Some(*entry),
            _ => None,
        }
    }
}

impl Default for ShmemPageState {
    fn default() -> Self {
        Self::Empty
    }
}

// -------------------------------------------------------------------
// ShmemInode
// -------------------------------------------------------------------

/// An shmem inode representing a tmpfs file or shared memory object.
///
/// Each inode has a fixed-size page array. Pages are allocated
/// on-demand when faulted in and can be swapped out by the reclaimer.
#[derive(Debug)]
pub struct ShmemInode {
    /// Inode number.
    ino: u64,
    /// Logical file size in bytes.
    size: u64,
    /// Per-page state array.
    pages: [ShmemPageState; MAX_PAGES_PER_INODE],
    /// Number of pages currently present in memory.
    nr_present: usize,
    /// Number of pages currently in swap.
    nr_swapped: usize,
    /// Number of allocated pages (pre-allocated via fallocate).
    nr_allocated: usize,
    /// Whether this inode is in use.
    in_use: bool,
    /// Creation timestamp (monotonic counter).
    created_at: u64,
    /// Last modification timestamp.
    modified_at: u64,
    /// Owner UID.
    uid: u32,
    /// Owner GID.
    gid: u32,
    /// Permission mode bits.
    mode: u32,
}

impl ShmemInode {
    /// Creates a new empty shmem inode.
    pub const fn new(ino: u64) -> Self {
        Self {
            ino,
            size: 0,
            pages: [const { ShmemPageState::Empty }; MAX_PAGES_PER_INODE],
            nr_present: 0,
            nr_swapped: 0,
            nr_allocated: 0,
            in_use: false,
            created_at: 0,
            modified_at: 0,
            uid: 0,
            gid: 0,
            mode: 0o644,
        }
    }

    /// Returns the inode number.
    pub const fn ino(&self) -> u64 {
        self.ino
    }

    /// Returns the file size in bytes.
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Returns the number of pages needed for the current size.
    pub const fn nr_pages(&self) -> usize {
        ((self.size + PAGE_SIZE - 1) / PAGE_SIZE) as usize
    }

    /// Returns the number of present (in-memory) pages.
    pub const fn nr_present(&self) -> usize {
        self.nr_present
    }

    /// Returns the number of swapped-out pages.
    pub const fn nr_swapped(&self) -> usize {
        self.nr_swapped
    }

    /// Faults in a page at the given index. If the page is empty,
    /// allocates a new page with the given PFN. If swapped, the
    /// caller should swap it in first.
    ///
    /// Returns the PFN of the present page.
    pub fn shmem_getpage(&mut self, index: usize, alloc_pfn: u64) -> Result<u64> {
        if index >= MAX_PAGES_PER_INODE {
            return Err(Error::InvalidArgument);
        }

        match self.pages[index] {
            ShmemPageState::Present(pfn) => Ok(pfn),
            ShmemPageState::Empty => {
                // Allocate a new page
                self.pages[index] = ShmemPageState::Present(alloc_pfn);
                self.nr_present += 1;
                self.nr_allocated += 1;
                // Extend size if needed
                let new_end = (index as u64 + 1) * PAGE_SIZE;
                if new_end > self.size {
                    self.size = new_end;
                }
                Ok(alloc_pfn)
            }
            ShmemPageState::Swapped(_entry) => {
                // Caller must swap in first, then call swap_in_page
                Err(Error::WouldBlock)
            }
        }
    }

    /// Completes a swap-in: replaces a swapped entry with a present
    /// page.
    pub fn swap_in_page(&mut self, index: usize, pfn: u64) -> Result<()> {
        if index >= MAX_PAGES_PER_INODE {
            return Err(Error::InvalidArgument);
        }
        match self.pages[index] {
            ShmemPageState::Swapped(_) => {
                self.pages[index] = ShmemPageState::Present(pfn);
                self.nr_swapped -= 1;
                self.nr_present += 1;
                Ok(())
            }
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Swaps out (writes back) a page, recording the swap entry.
    ///
    /// Returns the PFN of the page that was swapped out (caller
    /// must free it).
    pub fn shmem_writepage(&mut self, index: usize, swap_entry: u64) -> Result<u64> {
        if index >= MAX_PAGES_PER_INODE {
            return Err(Error::InvalidArgument);
        }
        match self.pages[index] {
            ShmemPageState::Present(pfn) => {
                self.pages[index] = ShmemPageState::Swapped(swap_entry);
                self.nr_present -= 1;
                self.nr_swapped += 1;
                Ok(pfn)
            }
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Truncates the inode to the given size, freeing/invalidating
    /// pages beyond the new size.
    ///
    /// Returns the number of pages freed (present) and swap entries
    /// invalidated.
    pub fn shmem_truncate(&mut self, new_size: u64) -> (usize, usize) {
        let new_nr_pages = ((new_size + PAGE_SIZE - 1) / PAGE_SIZE) as usize;
        let mut freed = 0;
        let mut swap_freed = 0;

        for i in new_nr_pages..MAX_PAGES_PER_INODE {
            match self.pages[i] {
                ShmemPageState::Present(_) => {
                    self.pages[i] = ShmemPageState::Empty;
                    self.nr_present -= 1;
                    freed += 1;
                }
                ShmemPageState::Swapped(_) => {
                    self.pages[i] = ShmemPageState::Empty;
                    self.nr_swapped -= 1;
                    swap_freed += 1;
                }
                ShmemPageState::Empty => {}
            }
        }

        self.size = new_size;
        (freed, swap_freed)
    }

    /// Hole-punches a range: frees pages in [start_idx, end_idx).
    ///
    /// Returns the number of pages freed.
    pub fn shmem_fallocate_punch(&mut self, start_idx: usize, end_idx: usize) -> usize {
        let end = end_idx.min(MAX_PAGES_PER_INODE);
        let mut freed = 0;

        for i in start_idx..end {
            match self.pages[i] {
                ShmemPageState::Present(_) => {
                    self.pages[i] = ShmemPageState::Empty;
                    self.nr_present -= 1;
                    freed += 1;
                }
                ShmemPageState::Swapped(_) => {
                    self.pages[i] = ShmemPageState::Empty;
                    self.nr_swapped -= 1;
                    freed += 1;
                }
                ShmemPageState::Empty => {}
            }
        }
        freed
    }

    /// Pre-allocates pages in [start_idx, end_idx) using provided PFNs.
    pub fn shmem_fallocate_alloc(&mut self, start_idx: usize, pfns: &[u64]) -> Result<usize> {
        let mut allocated = 0;
        for (i, pfn) in pfns.iter().enumerate() {
            let idx = start_idx + i;
            if idx >= MAX_PAGES_PER_INODE {
                break;
            }
            if self.pages[idx] == ShmemPageState::Empty {
                self.pages[idx] = ShmemPageState::Present(*pfn);
                self.nr_present += 1;
                self.nr_allocated += 1;
                allocated += 1;
            }
        }
        let new_end = ((start_idx + pfns.len()) as u64) * PAGE_SIZE;
        if new_end > self.size {
            self.size = new_end;
        }
        Ok(allocated)
    }

    /// Sets ownership and permission.
    pub fn set_attr(&mut self, uid: u32, gid: u32, mode: u32) {
        self.uid = uid;
        self.gid = gid;
        self.mode = mode;
    }
}

impl Default for ShmemInode {
    fn default() -> Self {
        Self::new(0)
    }
}

// -------------------------------------------------------------------
// ShmemStats
// -------------------------------------------------------------------

/// Shmem filesystem statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct ShmemStats {
    /// Total pages allocated.
    pub total_allocated: u64,
    /// Total pages freed.
    pub total_freed: u64,
    /// Total pages swapped out.
    pub total_swapped_out: u64,
    /// Total pages swapped in.
    pub total_swapped_in: u64,
    /// Total hole-punch operations.
    pub total_hole_punches: u64,
    /// Total truncate operations.
    pub total_truncates: u64,
    /// Current total present pages across all inodes.
    pub current_present: u64,
}

impl ShmemStats {
    /// Creates new zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_allocated: 0,
            total_freed: 0,
            total_swapped_out: 0,
            total_swapped_in: 0,
            total_hole_punches: 0,
            total_truncates: 0,
            current_present: 0,
        }
    }
}

// -------------------------------------------------------------------
// ShmemFs
// -------------------------------------------------------------------

/// Shmem filesystem manager — manages a pool of shmem inodes.
pub struct ShmemFs {
    /// Inode pool.
    inodes: [ShmemInode; MAX_INODES],
    /// Number of active inodes.
    active_count: usize,
    /// Next inode number to assign.
    next_ino: u64,
    /// Statistics.
    stats: ShmemStats,
    /// Maximum total pages across all inodes.
    max_pages: usize,
    /// Current total pages across all inodes.
    current_pages: usize,
}

impl ShmemFs {
    /// Creates a new shmem filesystem.
    pub const fn new() -> Self {
        Self {
            inodes: [const { ShmemInode::new(0) }; MAX_INODES],
            active_count: 0,
            next_ino: 1,
            stats: ShmemStats::new(),
            max_pages: MAX_INODES * MAX_PAGES_PER_INODE,
            current_pages: 0,
        }
    }

    /// Sets the maximum total pages.
    pub fn set_max_pages(&mut self, max: usize) {
        self.max_pages = max;
    }

    /// Creates a new shmem inode. Returns the inode number.
    pub fn create_inode(&mut self) -> Result<u64> {
        if self.active_count >= MAX_INODES {
            return Err(Error::OutOfMemory);
        }
        let slot = self.find_free_slot()?;
        let ino = self.next_ino;
        self.next_ino += 1;
        self.inodes[slot] = ShmemInode::new(ino);
        self.inodes[slot].in_use = true;
        self.active_count += 1;
        Ok(ino)
    }

    /// Removes an inode by inode number, freeing all its pages.
    pub fn destroy_inode(&mut self, ino: u64) -> Result<()> {
        let slot = self.find_inode(ino)?;
        let freed = self.inodes[slot].nr_present + self.inodes[slot].nr_swapped;
        self.current_pages = self.current_pages.saturating_sub(freed);
        self.stats.total_freed += freed as u64;
        self.inodes[slot] = ShmemInode::new(0);
        self.active_count -= 1;
        Ok(())
    }

    /// Faults in a page for an inode.
    pub fn getpage(&mut self, ino: u64, index: usize, alloc_pfn: u64) -> Result<u64> {
        let slot = self.find_inode(ino)?;
        let was_present = self.inodes[slot].pages[index] != ShmemPageState::Empty;
        let pfn = self.inodes[slot].shmem_getpage(index, alloc_pfn)?;
        if !was_present {
            self.current_pages += 1;
            self.stats.total_allocated += 1;
            self.stats.current_present += 1;
        }
        Ok(pfn)
    }

    /// Swaps out a page.
    pub fn writepage(&mut self, ino: u64, index: usize, swap_entry: u64) -> Result<u64> {
        let slot = self.find_inode(ino)?;
        let pfn = self.inodes[slot].shmem_writepage(index, swap_entry)?;
        self.stats.total_swapped_out += 1;
        self.stats.current_present -= 1;
        Ok(pfn)
    }

    /// Truncates an inode.
    pub fn truncate(&mut self, ino: u64, new_size: u64) -> Result<(usize, usize)> {
        let slot = self.find_inode(ino)?;
        let (freed, swap_freed) = self.inodes[slot].shmem_truncate(new_size);
        self.current_pages = self.current_pages.saturating_sub(freed + swap_freed);
        self.stats.total_freed += freed as u64;
        self.stats.total_truncates += 1;
        Ok((freed, swap_freed))
    }

    /// Hole-punches a range in an inode.
    pub fn fallocate_punch(&mut self, ino: u64, start_idx: usize, end_idx: usize) -> Result<usize> {
        let slot = self.find_inode(ino)?;
        let freed = self.inodes[slot].shmem_fallocate_punch(start_idx, end_idx);
        self.current_pages = self.current_pages.saturating_sub(freed);
        self.stats.total_freed += freed as u64;
        self.stats.total_hole_punches += 1;
        Ok(freed)
    }

    /// Returns a reference to the statistics.
    pub const fn stats(&self) -> &ShmemStats {
        &self.stats
    }

    /// Returns the number of active inodes.
    pub const fn active_count(&self) -> usize {
        self.active_count
    }

    /// Returns the current total pages in use.
    pub const fn current_pages(&self) -> usize {
        self.current_pages
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Finds a free inode slot.
    fn find_free_slot(&self) -> Result<usize> {
        for i in 0..MAX_INODES {
            if !self.inodes[i].in_use {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Finds an inode by inode number.
    fn find_inode(&self, ino: u64) -> Result<usize> {
        for i in 0..MAX_INODES {
            if self.inodes[i].in_use && self.inodes[i].ino == ino {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }
}

impl Default for ShmemFs {
    fn default() -> Self {
        Self::new()
    }
}
