// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! hugetlbfs — Huge page filesystem.
//!
//! Provides a filesystem interface for allocating and managing huge
//! pages (2 MiB and 1 GiB). Applications `mmap()` files from
//! hugetlbfs to obtain huge-page-backed memory regions, reducing
//! TLB pressure for memory-intensive workloads.
//!
//! # Design
//!
//! - [`HugetlbPageSize`] — supported huge page sizes (2M, 1G)
//! - [`HugetlbPage`] — a single huge page with PFN and allocation state
//! - [`HugetlbPool`] — manages pools of 2M (512) and 1G (16) pages
//! - [`HugetlbInode`] — inode backed by huge pages (up to 64 pages)
//! - [`HugetlbFs`] — filesystem instance with pool and 128 inodes
//! - [`HugetlbRegistry`] — global registry (4 mount slots)
//!
//! # Usage
//!
//! ```text
//! mount -t hugetlbfs none /dev/hugepages
//! # then mmap() files from /dev/hugepages for huge-page memory
//! ```
//!
//! Reference: Linux `fs/hugetlbfs/`, `Documentation/admin-guide/mm/hugetlbpage.rst`.

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// 2 MiB huge page size in bytes.
const SIZE_2M: u64 = 2 * 1024 * 1024;

/// 1 GiB huge page size in bytes.
const SIZE_1G: u64 = 1024 * 1024 * 1024;

/// Maximum number of 2 MiB pages in the pool.
const MAX_2M_PAGES: usize = 512;

/// Maximum number of 1 GiB pages in the pool.
const MAX_1G_PAGES: usize = 16;

/// Maximum page indices per inode.
const MAX_PAGES_PER_INODE: usize = 64;

/// Maximum number of inodes.
const MAX_INODES: usize = 128;

/// Maximum name length for inode entries.
const MAX_NAME_LEN: usize = 255;

/// Maximum directory entries in the root.
const MAX_DIR_ENTRIES: usize = 128;

/// Maximum number of hugetlbfs mount instances.
const MAX_HUGETLB_MOUNTS: usize = 4;

// ── HugetlbPageSize ─────────────────────────────────────────────

/// Supported huge page sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HugetlbPageSize {
    /// 2 MiB huge page.
    Size2M,
    /// 1 GiB huge page.
    Size1G,
}

impl HugetlbPageSize {
    /// Return the page size in bytes.
    pub const fn bytes(self) -> u64 {
        match self {
            Self::Size2M => SIZE_2M,
            Self::Size1G => SIZE_1G,
        }
    }
}

// ── HugetlbPage ─────────────────────────────────────────────────

/// A single huge page tracked by the pool.
#[derive(Debug, Clone, Copy)]
pub struct HugetlbPage {
    /// Physical frame number.
    pub pfn: u64,
    /// Page size category.
    pub size: HugetlbPageSize,
    /// Whether this page is currently allocated.
    pub allocated: bool,
}

impl HugetlbPage {
    /// Create an unallocated page entry.
    const fn free(pfn: u64, size: HugetlbPageSize) -> Self {
        Self {
            pfn,
            size,
            allocated: false,
        }
    }
}

// ── HugetlbPool ─────────────────────────────────────────────────

/// Pool of huge pages, managing both 2 MiB and 1 GiB page sets.
///
/// Pages are pre-populated at initialization and allocated/freed
/// on demand by the filesystem.
pub struct HugetlbPool {
    /// 2 MiB page pool.
    pages_2m: [HugetlbPage; MAX_2M_PAGES],
    /// 1 GiB page pool.
    pages_1g: [HugetlbPage; MAX_1G_PAGES],
}

impl HugetlbPool {
    /// Create a new pool with all pages pre-populated and free.
    pub fn new() -> Self {
        let mut pages_2m = [HugetlbPage::free(0, HugetlbPageSize::Size2M); MAX_2M_PAGES];
        for (idx, page) in pages_2m.iter_mut().enumerate() {
            page.pfn = idx as u64;
        }

        let mut pages_1g = [HugetlbPage::free(0, HugetlbPageSize::Size1G); MAX_1G_PAGES];
        for (idx, page) in pages_1g.iter_mut().enumerate() {
            page.pfn = (MAX_2M_PAGES + idx) as u64;
        }

        Self { pages_2m, pages_1g }
    }

    /// Allocate a huge page of the given size.
    ///
    /// Returns the pool index of the allocated page.
    pub fn alloc(&mut self, size: HugetlbPageSize) -> Result<usize> {
        let pool = match size {
            HugetlbPageSize::Size2M => &mut self.pages_2m[..],
            HugetlbPageSize::Size1G => &mut self.pages_1g[..],
        };
        for (idx, page) in pool.iter_mut().enumerate() {
            if !page.allocated {
                page.allocated = true;
                return Ok(idx);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Free a huge page by pool index.
    pub fn free(&mut self, size: HugetlbPageSize, idx: usize) -> Result<()> {
        let pool = match size {
            HugetlbPageSize::Size2M => &mut self.pages_2m[..],
            HugetlbPageSize::Size1G => &mut self.pages_1g[..],
        };
        if idx >= pool.len() || !pool[idx].allocated {
            return Err(Error::InvalidArgument);
        }
        pool[idx].allocated = false;
        Ok(())
    }

    /// Return the number of available (free) pages of the given size.
    pub fn available(&self, size: HugetlbPageSize) -> usize {
        let pool: &[HugetlbPage] = match size {
            HugetlbPageSize::Size2M => &self.pages_2m,
            HugetlbPageSize::Size1G => &self.pages_1g,
        };
        pool.iter().filter(|p| !p.allocated).count()
    }

    /// Return total capacity for the given page size.
    pub fn total(&self, size: HugetlbPageSize) -> usize {
        match size {
            HugetlbPageSize::Size2M => MAX_2M_PAGES,
            HugetlbPageSize::Size1G => MAX_1G_PAGES,
        }
    }
}

impl Default for HugetlbPool {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for HugetlbPool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HugetlbPool")
            .field("free_2m", &self.available(HugetlbPageSize::Size2M))
            .field("free_1g", &self.available(HugetlbPageSize::Size1G))
            .finish()
    }
}

// ── HugetlbInode ────────────────────────────────────────────────

/// An inode in hugetlbfs, backed by huge pages.
///
/// Each inode can reference up to [`MAX_PAGES_PER_INODE`] huge pages.
/// The page size is fixed at creation time.
#[derive(Debug, Clone)]
pub struct HugetlbInode {
    /// Inode number.
    pub ino: u64,
    /// File size in bytes.
    pub size: u64,
    /// Page size for this inode.
    pub page_size: HugetlbPageSize,
    /// Indices into the pool for allocated pages.
    pub page_indices: [Option<usize>; MAX_PAGES_PER_INODE],
    /// Number of pages allocated.
    pub page_count: usize,
    /// Whether this inode slot is active.
    pub active: bool,
}

impl HugetlbInode {
    /// Create an empty (inactive) inode.
    const fn empty() -> Self {
        Self {
            ino: 0,
            size: 0,
            page_size: HugetlbPageSize::Size2M,
            page_indices: [None; MAX_PAGES_PER_INODE],
            page_count: 0,
            active: false,
        }
    }
}

// ── HugetlbDirEntry ─────────────────────────────────────────────

/// A directory entry in the hugetlbfs root.
#[derive(Debug, Clone)]
struct HugetlbDirEntry {
    /// Entry name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: u8,
    /// Associated inode number.
    ino: u64,
}

impl HugetlbDirEntry {
    const fn empty() -> Self {
        Self {
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            ino: 0,
        }
    }
}

// ── HugetlbFs ───────────────────────────────────────────────────

/// Hugetlbfs filesystem instance.
///
/// Provides a pseudo-filesystem interface for allocating and managing
/// huge pages. Files created in hugetlbfs are backed by huge pages
/// from the pool.
pub struct HugetlbFs {
    /// Huge page pool.
    pool: HugetlbPool,
    /// Inode table.
    inodes: [HugetlbInode; MAX_INODES],
    /// Root directory entries.
    dir_entries: [Option<HugetlbDirEntry>; MAX_DIR_ENTRIES],
    /// Number of active directory entries.
    dir_count: usize,
    /// Next inode number.
    next_ino: u64,
    /// Whether the filesystem is mounted.
    mounted: bool,
    /// Default page size for new files.
    default_page_size: HugetlbPageSize,
}

impl HugetlbFs {
    /// Create a new hugetlbfs instance with default 2M page size.
    pub fn new() -> Self {
        const EMPTY_INODE: HugetlbInode = HugetlbInode::empty();
        const NONE_ENTRY: Option<HugetlbDirEntry> = None;

        Self {
            pool: HugetlbPool::new(),
            inodes: [EMPTY_INODE; MAX_INODES],
            dir_entries: [NONE_ENTRY; MAX_DIR_ENTRIES],
            dir_count: 0,
            next_ino: 1,
            mounted: false,
            default_page_size: HugetlbPageSize::Size2M,
        }
    }

    /// Create a hugetlbfs instance with a specific default page size.
    pub fn with_page_size(page_size: HugetlbPageSize) -> Self {
        let mut fs = Self::new();
        fs.default_page_size = page_size;
        fs
    }

    /// Mount the filesystem.
    pub fn mount(&mut self) -> Result<()> {
        if self.mounted {
            return Err(Error::Busy);
        }
        self.mounted = true;
        Ok(())
    }

    /// Unmount the filesystem.
    pub fn unmount(&mut self) -> Result<()> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        self.mounted = false;
        Ok(())
    }

    /// Find an inode slot by inode number.
    fn inode_slot(&self, ino: u64) -> Option<usize> {
        self.inodes.iter().position(|i| i.active && i.ino == ino)
    }

    /// Create a new file backed by huge pages.
    ///
    /// The file uses the filesystem's default page size.
    pub fn create(&mut self, name: &str) -> Result<u64> {
        self.create_with_size(name, self.default_page_size)
    }

    /// Create a new file with a specific page size.
    pub fn create_with_size(&mut self, name: &str, page_size: HugetlbPageSize) -> Result<u64> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        let name_bytes = name.as_bytes();
        if name_bytes.is_empty() || name_bytes.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.dir_count >= MAX_DIR_ENTRIES {
            return Err(Error::OutOfMemory);
        }

        // Check for duplicates.
        for entry in self.dir_entries.iter().flatten() {
            if entry.name_len as usize == name_bytes.len()
                && &entry.name[..entry.name_len as usize] == name_bytes
            {
                return Err(Error::AlreadyExists);
            }
        }

        // Allocate an inode.
        let ino = self.next_ino;
        self.next_ino += 1;

        let inode_slot = self
            .inodes
            .iter_mut()
            .position(|i| !i.active)
            .ok_or(Error::OutOfMemory)?;

        self.inodes[inode_slot] = HugetlbInode {
            ino,
            size: 0,
            page_size,
            page_indices: [None; MAX_PAGES_PER_INODE],
            page_count: 0,
            active: true,
        };

        // Add directory entry.
        let mut entry = HugetlbDirEntry::empty();
        entry.name[..name_bytes.len()].copy_from_slice(name_bytes);
        entry.name_len = name_bytes.len() as u8;
        entry.ino = ino;

        for slot in self.dir_entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(entry);
                self.dir_count += 1;
                return Ok(ino);
            }
        }

        // Roll back inode on directory entry failure.
        self.inodes[inode_slot].active = false;
        Err(Error::OutOfMemory)
    }

    /// Read from a hugetlbfs file.
    ///
    /// Since hugetlbfs files are memory-backed (via mmap), this
    /// returns the number of allocated bytes from offset. Actual
    /// content is not stored in this simplified model; reads return
    /// the page allocation status as zero-filled pages.
    pub fn read(&self, ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        let slot = self.inode_slot(ino).ok_or(Error::NotFound)?;
        let inode = &self.inodes[slot];

        if offset >= inode.size {
            return Ok(0);
        }

        let available = (inode.size - offset) as usize;
        let to_read = buf.len().min(available);
        // Huge pages are zero-initialized.
        buf[..to_read].fill(0);
        Ok(to_read)
    }

    /// Extend a hugetlbfs file by allocating additional huge pages.
    ///
    /// The `size` specifies the desired total file size in bytes.
    /// Pages are allocated as needed to cover the requested size.
    pub fn write(&mut self, ino: u64, size: u64) -> Result<u64> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        let slot = self.inode_slot(ino).ok_or(Error::NotFound)?;
        let page_bytes = self.inodes[slot].page_size.bytes();
        let current_pages = self.inodes[slot].page_count;
        let needed_pages = size.div_ceil(page_bytes) as usize;

        if needed_pages > MAX_PAGES_PER_INODE {
            return Err(Error::OutOfMemory);
        }

        // Allocate additional pages if needed.
        let page_size = self.inodes[slot].page_size;
        for i in current_pages..needed_pages {
            let pool_idx = self.pool.alloc(page_size)?;
            self.inodes[slot].page_indices[i] = Some(pool_idx);
            self.inodes[slot].page_count += 1;
        }

        self.inodes[slot].size = needed_pages as u64 * page_bytes;
        Ok(self.inodes[slot].size)
    }

    /// Unlink (remove) a file from hugetlbfs.
    ///
    /// Frees all huge pages associated with the inode.
    pub fn unlink(&mut self, name: &str) -> Result<()> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        let name_bytes = name.as_bytes();

        // Find and remove directory entry.
        let mut found_ino: Option<u64> = None;
        for slot in self.dir_entries.iter_mut() {
            if let Some(entry) = slot {
                if entry.name_len as usize == name_bytes.len()
                    && &entry.name[..entry.name_len as usize] == name_bytes
                {
                    found_ino = Some(entry.ino);
                    *slot = None;
                    self.dir_count -= 1;
                    break;
                }
            }
        }

        let ino = found_ino.ok_or(Error::NotFound)?;
        let inode_slot = self.inode_slot(ino).ok_or(Error::NotFound)?;

        // Free all pages.
        let page_size = self.inodes[inode_slot].page_size;
        for pool_idx in self.inodes[inode_slot].page_indices.iter().flatten() {
            let _ = self.pool.free(page_size, *pool_idx);
        }

        self.inodes[inode_slot].active = false;
        Ok(())
    }

    /// Return the number of active inodes.
    pub fn inode_count(&self) -> usize {
        self.inodes.iter().filter(|i| i.active).count()
    }

    /// Return a reference to the page pool.
    pub fn pool(&self) -> &HugetlbPool {
        &self.pool
    }
}

impl Default for HugetlbFs {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for HugetlbFs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HugetlbFs")
            .field("mounted", &self.mounted)
            .field("inode_count", &self.inode_count())
            .field("dir_entries", &self.dir_count)
            .field("pool", &self.pool)
            .finish()
    }
}

// ── HugetlbRegistry ────────────────────────────────────────────

/// Global registry of hugetlbfs mount instances.
///
/// Supports up to [`MAX_HUGETLB_MOUNTS`] concurrent mounts, each
/// potentially using a different default page size.
pub struct HugetlbRegistry {
    /// Mount path for each instance.
    paths: [[u8; MAX_NAME_LEN]; MAX_HUGETLB_MOUNTS],
    /// Path lengths.
    path_lens: [usize; MAX_HUGETLB_MOUNTS],
    /// Page size for each mount.
    page_sizes: [HugetlbPageSize; MAX_HUGETLB_MOUNTS],
    /// Whether each slot is in use.
    active: [bool; MAX_HUGETLB_MOUNTS],
}

impl HugetlbRegistry {
    /// Create a new empty registry.
    pub const fn new() -> Self {
        Self {
            paths: [[0u8; MAX_NAME_LEN]; MAX_HUGETLB_MOUNTS],
            path_lens: [0; MAX_HUGETLB_MOUNTS],
            page_sizes: [HugetlbPageSize::Size2M; MAX_HUGETLB_MOUNTS],
            active: [false; MAX_HUGETLB_MOUNTS],
        }
    }

    /// Register a hugetlbfs mount at the given path.
    pub fn register(&mut self, path: &str, page_size: HugetlbPageSize) -> Result<usize> {
        let path_bytes = path.as_bytes();
        if path_bytes.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        for (idx, used) in self.active.iter_mut().enumerate() {
            if !*used {
                self.paths[idx][..path_bytes.len()].copy_from_slice(path_bytes);
                self.path_lens[idx] = path_bytes.len();
                self.page_sizes[idx] = page_size;
                *used = true;
                return Ok(idx);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregister a mount by slot index.
    pub fn unregister(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_HUGETLB_MOUNTS || !self.active[idx] {
            return Err(Error::NotFound);
        }
        self.active[idx] = false;
        self.path_lens[idx] = 0;
        Ok(())
    }

    /// Find a mount by path.
    pub fn find(&self, path: &str) -> Option<usize> {
        let path_bytes = path.as_bytes();
        for (idx, used) in self.active.iter().enumerate() {
            if *used
                && self.path_lens[idx] == path_bytes.len()
                && &self.paths[idx][..self.path_lens[idx]] == path_bytes
            {
                return Some(idx);
            }
        }
        None
    }

    /// Return the number of active mounts.
    pub fn active_count(&self) -> usize {
        self.active.iter().filter(|a| **a).count()
    }
}

impl Default for HugetlbRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for HugetlbRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HugetlbRegistry")
            .field("active_mounts", &self.active_count())
            .finish()
    }
}
