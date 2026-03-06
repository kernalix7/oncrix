// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared memory filesystem — low-level tmpfs backing store.
//!
//! Provides the page-frame management layer that backs `tmpfs` and POSIX
//! shared memory objects (`shm_open`). Each file is represented by a
//! [`ShmemInode`] whose data lives in up to 256 [`ShmemPage`] entries,
//! each mapping a 4 KiB page frame.
//!
//! # Design
//!
//! ```text
//! ShmemFs
//!   ├── ShmemSuperblock  — accounting (blocks, inodes)
//!   └── inodes[512]      — fixed-size inode table
//!         └── ShmemInode
//!               ├── metadata (size, uid, gid, mode, timestamps)
//!               └── pages[256]  — page frame index
//!                     └── ShmemPage { pfn, dirty, swap_entry }
//! ```
//!
//! ## Swap integration
//!
//! [`shmem_writepage`] can mark a page as swapped-out by setting
//! `ShmemPage::swap_entry` to a non-zero swap slot. Subsequent
//! [`shmem_getpage`] calls on a swapped page must first swap it back in
//! (simulated here by clearing the swap entry).
//!
//! # References
//!
//! - Linux `mm/shmem.c` — `shmem_getpage_gfp()`, `shmem_writepage()`
//! - Linux `include/linux/shmem_fs.h`
//! - POSIX.1-2024 `shm_open(3)`, `mmap(2)`

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of inodes in the shmem filesystem.
pub const SHMEM_MAX_INODES: usize = 512;

/// Maximum number of page frames tracked per inode.
pub const SHMEM_MAX_PAGES: usize = 256;

/// Page size in bytes.
pub const SHMEM_PAGE_SIZE: usize = 4096;

/// Sentinel swap entry value meaning "not swapped".
pub const SWAP_ENTRY_NONE: u64 = 0;

// ── ShmemPage ────────────────────────────────────────────────────────────────

/// A single 4 KiB page frame associated with a shmem inode.
#[derive(Debug, Clone, Copy)]
pub struct ShmemPage {
    /// Physical page frame number (0 = not allocated).
    pub pfn: u64,
    /// Whether this page has unsaved modifications.
    pub dirty: bool,
    /// Swap entry (non-zero means the page is swapped out).
    pub swap_entry: u64,
}

impl ShmemPage {
    /// Constructs an unallocated page slot.
    pub const fn new() -> Self {
        Self {
            pfn: 0,
            dirty: false,
            swap_entry: SWAP_ENTRY_NONE,
        }
    }

    /// Returns `true` if this slot holds a valid (allocated) page.
    pub fn is_present(&self) -> bool {
        self.pfn != 0 && self.swap_entry == SWAP_ENTRY_NONE
    }

    /// Returns `true` if this page has been swapped out.
    pub fn is_swapped(&self) -> bool {
        self.swap_entry != SWAP_ENTRY_NONE
    }
}

impl Default for ShmemPage {
    fn default() -> Self {
        Self::new()
    }
}

// ── ShmemInode ────────────────────────────────────────────────────────────────

/// An inode in the shmem filesystem.
pub struct ShmemInode {
    /// Inode number.
    pub ino: u64,
    /// File size in bytes.
    pub size: u64,
    /// Hard link count.
    pub nlink: u32,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Permission bits and file type (S_IFREG | mode).
    pub mode: u32,
    /// Page frame table — one entry per 4 KiB page index.
    pub pages: [ShmemPage; SHMEM_MAX_PAGES],
    /// Last access time (monotonic ticks).
    pub atime: u64,
    /// Last data modification time (monotonic ticks).
    pub mtime: u64,
    /// Last status change time (monotonic ticks).
    pub ctime: u64,
    /// Whether this inode slot is allocated.
    pub allocated: bool,
    /// Next PFN to assign when allocating a new page (simulated allocator).
    next_pfn: u64,
}

impl ShmemInode {
    /// Constructs an empty inode slot.
    pub const fn new() -> Self {
        Self {
            ino: 0,
            size: 0,
            nlink: 0,
            uid: 0,
            gid: 0,
            mode: 0,
            pages: [const { ShmemPage::new() }; SHMEM_MAX_PAGES],
            atime: 0,
            mtime: 0,
            ctime: 0,
            allocated: false,
            next_pfn: 1,
        }
    }

    /// Allocates a new PFN for this inode (simulated physical allocator).
    fn alloc_pfn(&mut self) -> u64 {
        let pfn = self.next_pfn;
        self.next_pfn = self.next_pfn.wrapping_add(1);
        pfn
    }

    /// Returns the number of allocated (resident or swapped) pages.
    pub fn page_count(&self) -> usize {
        self.pages.iter().filter(|p| p.pfn != 0).count()
    }
}

impl Default for ShmemInode {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for ShmemInode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShmemInode")
            .field("ino", &self.ino)
            .field("size", &self.size)
            .field("nlink", &self.nlink)
            .field("mode", &self.mode)
            .field("pages_used", &self.page_count())
            .finish()
    }
}

// ── ShmemSuperblock ───────────────────────────────────────────────────────────

/// Accounting information for the shmem filesystem.
#[derive(Debug, Clone, Copy)]
pub struct ShmemSuperblock {
    /// Total block capacity (in page units).
    pub total_blocks: u64,
    /// Free blocks remaining.
    pub free_blocks: u64,
    /// Total inode capacity.
    pub total_inodes: u64,
    /// Free inode slots remaining.
    pub free_inodes: u64,
}

impl ShmemSuperblock {
    /// Constructs a superblock with default limits.
    pub const fn new() -> Self {
        Self {
            total_blocks: (SHMEM_MAX_INODES * SHMEM_MAX_PAGES) as u64,
            free_blocks: (SHMEM_MAX_INODES * SHMEM_MAX_PAGES) as u64,
            total_inodes: SHMEM_MAX_INODES as u64,
            free_inodes: SHMEM_MAX_INODES as u64,
        }
    }
}

impl Default for ShmemSuperblock {
    fn default() -> Self {
        Self::new()
    }
}

// ── ShmemStats ────────────────────────────────────────────────────────────────

/// Cumulative statistics for the shmem filesystem.
#[derive(Debug, Default, Clone, Copy)]
pub struct ShmemStats {
    /// Total pages allocated (includes re-allocations after swap-in).
    pub pages_allocated: u64,
    /// Total pages freed (via truncate or inode free).
    pub pages_freed: u64,
    /// Total pages written to swap.
    pub pages_swapped: u64,
    /// Total `shmem_getpage` calls.
    pub getpage_calls: u64,
}

impl ShmemStats {
    /// Constructs zeroed statistics.
    pub const fn new() -> Self {
        Self {
            pages_allocated: 0,
            pages_freed: 0,
            pages_swapped: 0,
            getpage_calls: 0,
        }
    }
}

// ── ShmemFs ───────────────────────────────────────────────────────────────────

/// Top-level shmem filesystem object.
pub struct ShmemFs {
    /// Filesystem accounting superblock.
    pub superblock: ShmemSuperblock,
    /// Fixed-size inode table.
    pub inodes: [ShmemInode; SHMEM_MAX_INODES],
    /// Cumulative statistics.
    pub stats: ShmemStats,
    /// Next inode number to assign.
    next_ino: u64,
}

impl ShmemFs {
    /// Constructs an empty shmem filesystem.
    pub const fn new() -> Self {
        Self {
            superblock: ShmemSuperblock::new(),
            inodes: [const { ShmemInode::new() }; SHMEM_MAX_INODES],
            stats: ShmemStats::new(),
            next_ino: 1,
        }
    }

    // ── Inode management ──────────────────────────────────────────────────────

    /// Allocates a new inode with the given `uid`, `gid`, and `mode`.
    ///
    /// Returns the inode number on success.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] — no free inode slots.
    pub fn alloc_inode(&mut self, uid: u32, gid: u32, mode: u32) -> Result<u64> {
        if self.superblock.free_inodes == 0 {
            return Err(Error::OutOfMemory);
        }
        let slot = self
            .inodes
            .iter()
            .position(|i| !i.allocated)
            .ok_or(Error::OutOfMemory)?;
        let ino = self.next_ino;
        self.next_ino = self.next_ino.wrapping_add(1);
        let inode = &mut self.inodes[slot];
        inode.ino = ino;
        inode.size = 0;
        inode.nlink = 1;
        inode.uid = uid;
        inode.gid = gid;
        inode.mode = mode;
        inode.allocated = true;
        inode.next_pfn = 1;
        self.superblock.free_inodes = self.superblock.free_inodes.saturating_sub(1);
        Ok(ino)
    }

    /// Frees the inode with number `ino`, releasing all its pages.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — no allocated inode with that number.
    pub fn free_inode(&mut self, ino: u64) -> Result<()> {
        let slot = self
            .inodes
            .iter()
            .position(|i| i.allocated && i.ino == ino)
            .ok_or(Error::NotFound)?;
        let freed_pages = self.inodes[slot].page_count() as u64;
        self.inodes[slot] = ShmemInode::new();
        self.superblock.free_blocks = self.superblock.free_blocks.saturating_add(freed_pages);
        self.superblock.free_inodes = self.superblock.free_inodes.wrapping_add(1);
        self.stats.pages_freed = self.stats.pages_freed.wrapping_add(freed_pages);
        Ok(())
    }

    /// Returns the table index for inode `ino`.
    fn inode_slot(&self, ino: u64) -> Result<usize> {
        self.inodes
            .iter()
            .position(|i| i.allocated && i.ino == ino)
            .ok_or(Error::NotFound)
    }

    // ── Page operations ───────────────────────────────────────────────────────

    /// Ensures the page at `index` for inode `ino` is resident and returns its
    /// PFN.
    ///
    /// If the page is swapped out it is swapped back in (swap entry cleared).
    /// If the page was never allocated a new PFN is assigned.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — inode `ino` does not exist.
    /// - [`Error::InvalidArgument`] — `index` ≥ `SHMEM_MAX_PAGES`.
    /// - [`Error::OutOfMemory`] — no free blocks.
    pub fn shmem_getpage(&mut self, ino: u64, index: usize) -> Result<u64> {
        if index >= SHMEM_MAX_PAGES {
            return Err(Error::InvalidArgument);
        }
        self.stats.getpage_calls = self.stats.getpage_calls.wrapping_add(1);
        let slot = self.inode_slot(ino)?;
        let page = &mut self.inodes[slot].pages[index];
        if page.is_swapped() {
            // Swap-in: clear the swap entry, keep the PFN.
            page.swap_entry = SWAP_ENTRY_NONE;
            page.dirty = false;
            return Ok(page.pfn);
        }
        if page.is_present() {
            return Ok(page.pfn);
        }
        // New page.
        if self.superblock.free_blocks == 0 {
            return Err(Error::OutOfMemory);
        }
        let pfn = self.inodes[slot].alloc_pfn();
        self.inodes[slot].pages[index].pfn = pfn;
        self.inodes[slot].pages[index].dirty = false;
        self.inodes[slot].pages[index].swap_entry = SWAP_ENTRY_NONE;
        self.superblock.free_blocks = self.superblock.free_blocks.saturating_sub(1);
        self.stats.pages_allocated = self.stats.pages_allocated.wrapping_add(1);
        Ok(pfn)
    }

    /// Writes `data` into the page at `index` for inode `ino`.
    ///
    /// If `data` is empty the page is swapped out (swap entry = PFN as a proxy
    /// swap slot). Otherwise the data is stored in the inode's page table and
    /// the page is marked dirty.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — inode does not exist.
    /// - [`Error::InvalidArgument`] — `index` out of range or data too large.
    /// - [`Error::OutOfMemory`] — no blocks available for a new page.
    pub fn shmem_writepage(&mut self, ino: u64, index: usize, data: &[u8]) -> Result<()> {
        if index >= SHMEM_MAX_PAGES {
            return Err(Error::InvalidArgument);
        }
        if data.len() > SHMEM_PAGE_SIZE {
            return Err(Error::InvalidArgument);
        }
        let slot = self.inode_slot(ino)?;

        if data.is_empty() {
            // Swap-out: record a proxy swap entry.
            let page = &mut self.inodes[slot].pages[index];
            if page.pfn != 0 {
                page.swap_entry = page.pfn; // use PFN as proxy swap handle
                page.dirty = false;
                self.stats.pages_swapped = self.stats.pages_swapped.wrapping_add(1);
            }
            return Ok(());
        }

        // Ensure the page is resident.
        let pfn = self.shmem_getpage(ino, index)?;
        let _ = pfn; // PFN is conceptually used for I/O
        let slot2 = self.inode_slot(ino)?;
        self.inodes[slot2].pages[index].dirty = true;
        // In a real system we would write `data` to the physical page backing `pfn`.
        // Here we record the write by updating the inode size if needed.
        let new_end = (index * SHMEM_PAGE_SIZE + data.len()) as u64;
        if self.inodes[slot2].size < new_end {
            self.inodes[slot2].size = new_end;
        }
        Ok(())
    }

    /// Truncates inode `ino` to `new_size` bytes, freeing pages beyond the new
    /// end.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — inode does not exist.
    pub fn shmem_truncate(&mut self, ino: u64, new_size: u64) -> Result<()> {
        let slot = self.inode_slot(ino)?;
        let old_size = self.inodes[slot].size;
        if new_size >= old_size {
            // Extending — just update size; pages are lazily allocated.
            self.inodes[slot].size = new_size;
            return Ok(());
        }
        // Free pages beyond the new end.
        let first_free_page =
            ((new_size + SHMEM_PAGE_SIZE as u64 - 1) / SHMEM_PAGE_SIZE as u64) as usize;
        let mut freed = 0u64;
        for i in first_free_page..SHMEM_MAX_PAGES {
            if self.inodes[slot].pages[i].pfn != 0 {
                self.inodes[slot].pages[i] = ShmemPage::new();
                freed = freed.wrapping_add(1);
            }
        }
        self.inodes[slot].size = new_size;
        self.superblock.free_blocks = self.superblock.free_blocks.saturating_add(freed);
        self.stats.pages_freed = self.stats.pages_freed.wrapping_add(freed);
        Ok(())
    }

    /// Returns a reference to the inode with number `ino`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — inode not found.
    pub fn get_inode(&self, ino: u64) -> Result<&ShmemInode> {
        self.inodes
            .iter()
            .find(|i| i.allocated && i.ino == ino)
            .ok_or(Error::NotFound)
    }

    /// Returns a snapshot of the current statistics.
    pub fn stats(&self) -> ShmemStats {
        self.stats
    }
}

impl Default for ShmemFs {
    fn default() -> Self {
        Self::new()
    }
}

// ── Free-standing VFS helpers ─────────────────────────────────────────────────

/// Convenience wrapper: create a shmem file with default permissions.
///
/// `mode` should include the file type bits (e.g. `0o100644` for a regular
/// file).
pub fn shmem_create(fs: &mut ShmemFs, uid: u32, gid: u32, mode: u32) -> Result<u64> {
    fs.alloc_inode(uid, gid, mode)
}

/// Convenience wrapper: unlink / remove a shmem file.
pub fn shmem_unlink(fs: &mut ShmemFs, ino: u64) -> Result<()> {
    fs.free_inode(ino)
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_and_free_inode() {
        let mut fs = ShmemFs::new();
        let ino = fs.alloc_inode(0, 0, 0o100644).unwrap();
        assert_eq!(fs.get_inode(ino).unwrap().ino, ino);
        fs.free_inode(ino).unwrap();
        assert!(matches!(fs.get_inode(ino), Err(Error::NotFound)));
    }

    #[test]
    fn getpage_allocates_once() {
        let mut fs = ShmemFs::new();
        let ino = fs.alloc_inode(0, 0, 0o100644).unwrap();
        let pfn1 = fs.shmem_getpage(ino, 0).unwrap();
        let pfn2 = fs.shmem_getpage(ino, 0).unwrap();
        assert_eq!(pfn1, pfn2); // same page, not re-allocated
        assert_eq!(fs.stats().pages_allocated, 1);
    }

    #[test]
    fn writepage_updates_size() {
        let mut fs = ShmemFs::new();
        let ino = fs.alloc_inode(1000, 1000, 0o100600).unwrap();
        let data = [0xABu8; 512];
        fs.shmem_writepage(ino, 0, &data).unwrap();
        assert_eq!(fs.get_inode(ino).unwrap().size, 512);
    }

    #[test]
    fn swap_out_and_back_in() {
        let mut fs = ShmemFs::new();
        let ino = fs.alloc_inode(0, 0, 0o100644).unwrap();
        fs.shmem_getpage(ino, 3).unwrap();
        // Swap out.
        fs.shmem_writepage(ino, 3, &[]).unwrap();
        assert!(fs.inodes[0].pages[3].is_swapped());
        assert_eq!(fs.stats().pages_swapped, 1);
        // Swap back in.
        let pfn = fs.shmem_getpage(ino, 3).unwrap();
        assert_ne!(pfn, 0);
        assert!(!fs.inodes[0].pages[3].is_swapped());
    }

    #[test]
    fn truncate_frees_pages() {
        let mut fs = ShmemFs::new();
        let ino = fs.alloc_inode(0, 0, 0o100644).unwrap();
        // Allocate two pages.
        fs.shmem_getpage(ino, 0).unwrap();
        fs.shmem_getpage(ino, 1).unwrap();
        let before = fs.superblock.free_blocks;
        fs.shmem_truncate(ino, 0).unwrap();
        assert!(fs.superblock.free_blocks > before);
        assert_eq!(fs.stats().pages_freed, 2);
    }
}
