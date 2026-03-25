// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! tmpfs transparent huge pages — huge page support for tmpfs.
//!
//! Extends the standard tmpfs filesystem with transparent huge page (THP)
//! allocation, allowing tmpfs-backed memory to use 2 MiB PMD-level pages
//! instead of 4 KiB base pages.
//!
//! # Allocation policies
//!
//! Each tmpfs mount can choose a THP policy:
//!
//! - **Never**: always use 4 KiB pages (default tmpfs behavior).
//! - **Always**: always attempt 2 MiB allocation, fallback to 4 KiB.
//! - **Within_size**: use huge pages only within the file size rounded
//!   up to the huge page boundary.
//! - **Advise**: use huge pages only for regions that have been
//!   `madvise(MADV_HUGEPAGE)`'d.
//!
//! # PMD pages
//!
//! A PMD (Page Middle Directory) page is a single 2 MiB page that replaces
//! 512 contiguous 4 KiB pages in the page table.  This reduces TLB
//! pressure significantly for large files.
//!
//! # Splitting and collapsing
//!
//! - **Splitting**: when a partial write or mmap touches only part of a
//!   huge page, the huge page is split into 512 base pages.
//! - **Collapsing**: when 512 contiguous base pages become eligible, they
//!   are collapsed back into a single huge page (background scan).
//!
//! # Reference
//!
//! Linux `mm/shmem.c` (huge page support), `Documentation/admin-guide/mm/transhuge.rst`.

extern crate alloc;

use crate::inode::{FileMode, FileType, Inode, InodeNumber, InodeOps};
use alloc::string::String;
use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Base page size (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Huge page size (2 MiB = 512 base pages).
const HUGE_PAGE_SIZE: usize = 2 * 1024 * 1024;

/// Number of base pages in a huge page.
const PAGES_PER_HUGE: usize = HUGE_PAGE_SIZE / PAGE_SIZE;

/// Maximum inodes.
const MAX_INODES: usize = 512;

/// Maximum directory entries per directory.
const MAX_DIR_ENTRIES: usize = 128;

/// Maximum file data size (limited for in-memory model).
const MAX_FILE_DATA: usize = 8 * 1024 * 1024; // 8 MiB

/// Maximum filename length.
const MAX_NAME_LEN: usize = 255;

/// Maximum page entries tracked per file.
const MAX_PAGE_ENTRIES: usize = 4096;

// ── THP policy ───────────────────────────────────────────────────────────────

/// Transparent huge page allocation policy for a tmpfs mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HugePagePolicy {
    /// Never allocate huge pages.
    Never,
    /// Always try huge pages, fallback to base pages.
    Always,
    /// Use huge pages only within file size (rounded to huge page boundary).
    WithinSize,
    /// Use huge pages only for madvise'd regions.
    Advise,
}

impl HugePagePolicy {
    /// Parse from a mount option string.
    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "never" => Ok(Self::Never),
            "always" => Ok(Self::Always),
            "within_size" => Ok(Self::WithinSize),
            "advise" => Ok(Self::Advise),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Convert to a string for mount options.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::Always => "always",
            Self::WithinSize => "within_size",
            Self::Advise => "advise",
        }
    }
}

// ── Page descriptor ──────────────────────────────────────────────────────────

/// Page type: base page or huge page (PMD).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageType {
    /// Standard 4 KiB base page.
    Base,
    /// 2 MiB PMD (huge) page.
    Huge,
}

/// A page entry in the file's page table.
#[derive(Debug, Clone, Copy)]
pub struct PageEntry {
    /// File offset this page covers (page-aligned).
    pub offset: usize,
    /// Page type.
    pub page_type: PageType,
    /// Whether this page has been advised for huge pages.
    pub advised: bool,
    /// Reference count (for shared mappings).
    pub refcount: u32,
}

impl PageEntry {
    /// Size of this page entry.
    pub fn size(&self) -> usize {
        match self.page_type {
            PageType::Base => PAGE_SIZE,
            PageType::Huge => HUGE_PAGE_SIZE,
        }
    }
}

// ── Statistics ───────────────────────────────────────────────────────────────

/// Huge page statistics for a tmpfs mount.
#[derive(Debug, Clone, Copy, Default)]
pub struct HugePageStats {
    /// Number of huge pages currently allocated.
    pub huge_pages_allocated: u64,
    /// Number of base pages currently allocated.
    pub base_pages_allocated: u64,
    /// Total huge page allocation attempts.
    pub huge_alloc_attempts: u64,
    /// Successful huge page allocations.
    pub huge_alloc_success: u64,
    /// Failed huge page allocations (fell back to base pages).
    pub huge_alloc_failures: u64,
    /// Number of huge page splits performed.
    pub splits: u64,
    /// Number of collapses (base → huge) performed.
    pub collapses: u64,
}

impl HugePageStats {
    /// Huge page allocation success rate as a percentage.
    pub fn success_rate_percent(&self) -> u32 {
        if self.huge_alloc_attempts == 0 {
            return 0;
        }
        ((self.huge_alloc_success * 100) / self.huge_alloc_attempts) as u32
    }

    /// Total memory in use (bytes).
    pub fn total_memory(&self) -> u64 {
        self.huge_pages_allocated * HUGE_PAGE_SIZE as u64
            + self.base_pages_allocated * PAGE_SIZE as u64
    }
}

// ── Mount options ────────────────────────────────────────────────────────────

/// Per-mount configuration for tmpfs huge page support.
#[derive(Debug, Clone, Copy)]
pub struct HugeMountOptions {
    /// THP policy.
    pub policy: HugePagePolicy,
    /// Maximum file size allowed on this mount (0 = unlimited within model).
    pub max_size: usize,
    /// Whether to allow splitting of huge pages.
    pub allow_split: bool,
    /// Whether background collapse scanning is enabled.
    pub collapse_enabled: bool,
    /// Minimum number of contiguous base pages required for collapse.
    pub collapse_threshold: usize,
}

impl Default for HugeMountOptions {
    fn default() -> Self {
        Self {
            policy: HugePagePolicy::Never,
            max_size: MAX_FILE_DATA,
            allow_split: true,
            collapse_enabled: true,
            collapse_threshold: PAGES_PER_HUGE,
        }
    }
}

// ── tmpfs inode ──────────────────────────────────────────────────────────────

/// tmpfs inode with huge page tracking.
#[derive(Debug, Clone)]
pub struct TmpfsHugeInode {
    /// Inode number.
    pub ino: u64,
    /// File type.
    pub file_type: FileType,
    /// Permission bits.
    pub mode: u16,
    /// File size in bytes.
    pub size: u64,
    /// Hard link count.
    pub nlink: u32,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Page entries for this file.
    pub pages: Vec<PageEntry>,
}

impl TmpfsHugeInode {
    /// Create a new regular file inode.
    pub fn new_file(ino: u64, mode: u16) -> Self {
        Self {
            ino,
            file_type: FileType::Regular,
            mode,
            size: 0,
            nlink: 1,
            uid: 0,
            gid: 0,
            pages: Vec::new(),
        }
    }

    /// Create a new directory inode.
    pub fn new_dir(ino: u64, mode: u16) -> Self {
        Self {
            ino,
            file_type: FileType::Directory,
            mode,
            size: 0,
            nlink: 2,
            uid: 0,
            gid: 0,
            pages: Vec::new(),
        }
    }

    /// Convert to a VFS [`Inode`].
    pub fn to_vfs_inode(&self) -> Inode {
        let mut vfs = Inode::new(InodeNumber(self.ino), self.file_type, FileMode(self.mode));
        vfs.size = self.size;
        vfs.nlink = self.nlink;
        vfs.uid = self.uid;
        vfs.gid = self.gid;
        vfs
    }

    /// Count huge pages for this inode.
    pub fn huge_page_count(&self) -> usize {
        self.pages
            .iter()
            .filter(|p| p.page_type == PageType::Huge)
            .count()
    }

    /// Count base pages for this inode.
    pub fn base_page_count(&self) -> usize {
        self.pages
            .iter()
            .filter(|p| p.page_type == PageType::Base)
            .count()
    }
}

// ── Directory entry ──────────────────────────────────────────────────────────

/// In-memory directory entry.
#[derive(Debug, Clone)]
struct TmpfsHugeDirEntry {
    /// Target inode number.
    ino: u64,
    /// File type.
    file_type: FileType,
    /// Entry name.
    name: String,
}

// ── File data storage ────────────────────────────────────────────────────────

/// In-memory file data with page tracking.
struct TmpfsHugeFileData {
    /// Owning inode number.
    ino: u64,
    /// Raw data.
    data: Vec<u8>,
}

// ── Mounted filesystem ───────────────────────────────────────────────────────

/// Mounted tmpfs with transparent huge page support.
///
/// Extends standard tmpfs with huge page allocation, splitting, and
/// collapsing capabilities.
pub struct TmpfsHugeFs {
    /// Mount options.
    opts: HugeMountOptions,
    /// Statistics.
    stats: HugePageStats,
    /// Inode table.
    inodes: Vec<TmpfsHugeInode>,
    /// Directory entries (parent_ino, entry).
    dir_entries: Vec<(u64, TmpfsHugeDirEntry)>,
    /// File data blobs.
    file_data: Vec<TmpfsHugeFileData>,
    /// Next inode number.
    next_ino: u64,
}

impl TmpfsHugeFs {
    /// Create a new tmpfs with huge page support.
    pub fn new(opts: HugeMountOptions) -> Self {
        let root = TmpfsHugeInode::new_dir(1, 0o1777); // sticky bit
        Self {
            opts,
            stats: HugePageStats::default(),
            inodes: alloc::vec![root],
            dir_entries: Vec::new(),
            file_data: Vec::new(),
            next_ino: 2,
        }
    }

    /// Return statistics.
    pub fn stats(&self) -> &HugePageStats {
        &self.stats
    }

    /// Return mount options.
    pub fn mount_opts(&self) -> &HugeMountOptions {
        &self.opts
    }

    /// Set the THP policy at runtime.
    pub fn set_policy(&mut self, policy: HugePagePolicy) {
        self.opts.policy = policy;
    }

    // ── Page allocation ──────────────────────────────────────────────

    /// Decide whether to attempt huge page allocation for a given offset.
    fn should_use_huge(&self, offset: usize, file_size: u64, advised: bool) -> bool {
        match self.opts.policy {
            HugePagePolicy::Never => false,
            HugePagePolicy::Always => true,
            HugePagePolicy::WithinSize => {
                // Use huge pages within the file size rounded up.
                let rounded =
                    ((file_size as usize) + HUGE_PAGE_SIZE - 1) / HUGE_PAGE_SIZE * HUGE_PAGE_SIZE;
                offset + HUGE_PAGE_SIZE <= rounded
            }
            HugePagePolicy::Advise => advised,
        }
    }

    /// Allocate pages for a file region.
    fn allocate_pages(
        &mut self,
        ino: u64,
        offset: usize,
        length: usize,
        file_size: u64,
    ) -> Result<()> {
        let inode_idx = self
            .inodes
            .iter()
            .position(|i| i.ino == ino)
            .ok_or(Error::NotFound)?;

        let end = offset + length;
        let mut pos = offset;

        while pos < end {
            // Check if we already have a page covering this offset.
            let existing = self.inodes[inode_idx]
                .pages
                .iter()
                .any(|p| pos >= p.offset && pos < p.offset + p.size());
            if existing {
                pos += PAGE_SIZE;
                continue;
            }

            let huge_aligned = pos % HUGE_PAGE_SIZE == 0;
            let enough_room = pos + HUGE_PAGE_SIZE <= end;
            let advised = false; // simplified

            if huge_aligned && enough_room && self.should_use_huge(pos, file_size, advised) {
                self.stats.huge_alloc_attempts += 1;
                // Simulate: huge allocation succeeds if aligned.
                if self.inodes[inode_idx].pages.len() < MAX_PAGE_ENTRIES {
                    self.inodes[inode_idx].pages.push(PageEntry {
                        offset: pos,
                        page_type: PageType::Huge,
                        advised,
                        refcount: 1,
                    });
                    self.stats.huge_alloc_success += 1;
                    self.stats.huge_pages_allocated += 1;
                    pos += HUGE_PAGE_SIZE;
                    continue;
                }
                self.stats.huge_alloc_failures += 1;
            }

            // Fallback to base page.
            if self.inodes[inode_idx].pages.len() < MAX_PAGE_ENTRIES {
                self.inodes[inode_idx].pages.push(PageEntry {
                    offset: pos,
                    page_type: PageType::Base,
                    advised: false,
                    refcount: 1,
                });
                self.stats.base_pages_allocated += 1;
            }
            pos += PAGE_SIZE;
        }
        Ok(())
    }

    // ── Splitting ────────────────────────────────────────────────────

    /// Split a huge page at the given file offset into base pages.
    pub fn split_huge_page(&mut self, ino: u64, offset: usize) -> Result<()> {
        if !self.opts.allow_split {
            return Err(Error::NotImplemented);
        }

        let inode_idx = self
            .inodes
            .iter()
            .position(|i| i.ino == ino)
            .ok_or(Error::NotFound)?;

        // Find the huge page containing this offset.
        let page_idx = self.inodes[inode_idx]
            .pages
            .iter()
            .position(|p| {
                p.page_type == PageType::Huge
                    && offset >= p.offset
                    && offset < p.offset + HUGE_PAGE_SIZE
            })
            .ok_or(Error::NotFound)?;

        let huge_offset = self.inodes[inode_idx].pages[page_idx].offset;
        let advised = self.inodes[inode_idx].pages[page_idx].advised;

        // Remove the huge page.
        self.inodes[inode_idx].pages.remove(page_idx);
        self.stats.huge_pages_allocated = self.stats.huge_pages_allocated.saturating_sub(1);

        // Create base pages.
        let count = PAGES_PER_HUGE.min(MAX_PAGE_ENTRIES - self.inodes[inode_idx].pages.len());
        for i in 0..count {
            self.inodes[inode_idx].pages.push(PageEntry {
                offset: huge_offset + i * PAGE_SIZE,
                page_type: PageType::Base,
                advised,
                refcount: 1,
            });
            self.stats.base_pages_allocated += 1;
        }
        self.stats.splits += 1;
        Ok(())
    }

    // ── Collapsing ───────────────────────────────────────────────────

    /// Attempt to collapse contiguous base pages into a huge page.
    pub fn try_collapse(&mut self, ino: u64, offset: usize) -> Result<bool> {
        if !self.opts.collapse_enabled {
            return Ok(false);
        }
        // Offset must be huge-page-aligned.
        if offset % HUGE_PAGE_SIZE != 0 {
            return Ok(false);
        }

        let inode_idx = self
            .inodes
            .iter()
            .position(|i| i.ino == ino)
            .ok_or(Error::NotFound)?;

        // Check that we have PAGES_PER_HUGE contiguous base pages.
        let mut found = 0usize;
        for p in &self.inodes[inode_idx].pages {
            if p.page_type == PageType::Base
                && p.offset >= offset
                && p.offset < offset + HUGE_PAGE_SIZE
            {
                found += 1;
            }
        }

        if found < self.opts.collapse_threshold {
            return Ok(false);
        }

        // Remove the base pages in this range.
        self.inodes[inode_idx].pages.retain(|p| {
            !(p.page_type == PageType::Base
                && p.offset >= offset
                && p.offset < offset + HUGE_PAGE_SIZE)
        });
        self.stats.base_pages_allocated =
            self.stats.base_pages_allocated.saturating_sub(found as u64);

        // Add a huge page.
        self.inodes[inode_idx].pages.push(PageEntry {
            offset,
            page_type: PageType::Huge,
            advised: false,
            refcount: 1,
        });
        self.stats.huge_pages_allocated += 1;
        self.stats.collapses += 1;
        Ok(true)
    }

    /// Run a collapse scan across all files.
    pub fn collapse_scan(&mut self) -> u64 {
        let mut collapsed = 0u64;
        let inos: Vec<u64> = self
            .inodes
            .iter()
            .filter(|i| i.file_type == FileType::Regular)
            .map(|i| i.ino)
            .collect();
        for ino in inos {
            let file_size = self
                .inodes
                .iter()
                .find(|i| i.ino == ino)
                .map(|i| i.size)
                .unwrap_or(0);
            let mut offset = 0;
            while offset < file_size as usize {
                if let Ok(true) = self.try_collapse(ino, offset) {
                    collapsed += 1;
                }
                offset += HUGE_PAGE_SIZE;
            }
        }
        collapsed
    }

    // ── Advise ───────────────────────────────────────────────────────

    /// Mark a region as advised for huge pages (MADV_HUGEPAGE equivalent).
    pub fn advise_hugepage(&mut self, ino: u64, offset: usize, length: usize) -> Result<()> {
        let inode_idx = self
            .inodes
            .iter()
            .position(|i| i.ino == ino)
            .ok_or(Error::NotFound)?;
        let end = offset + length;
        for page in &mut self.inodes[inode_idx].pages {
            if page.offset >= offset && page.offset < end {
                page.advised = true;
            }
        }
        Ok(())
    }

    // ── Internal helpers ─────────────────────────────────────────────

    /// Find an inode by number.
    fn find_inode(&self, ino: u64) -> Result<&TmpfsHugeInode> {
        self.inodes
            .iter()
            .find(|i| i.ino == ino)
            .ok_or(Error::NotFound)
    }

    /// Allocate a new inode number.
    fn alloc_ino(&mut self) -> Result<u64> {
        if self.inodes.len() >= MAX_INODES {
            return Err(Error::OutOfMemory);
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        Ok(ino)
    }

    /// Find a directory entry by parent inode and name.
    fn find_dir_entry(&self, parent_ino: u64, name: &str) -> Result<&TmpfsHugeDirEntry> {
        self.dir_entries
            .iter()
            .find(|(p, e)| *p == parent_ino && e.name == name)
            .map(|(_, e)| e)
            .ok_or(Error::NotFound)
    }

    /// Count directory entries for a parent.
    fn dir_entry_count(&self, parent_ino: u64) -> usize {
        self.dir_entries
            .iter()
            .filter(|(p, _)| *p == parent_ino)
            .count()
    }

    /// Get file data.
    fn get_file_data(&self, ino: u64) -> Option<&TmpfsHugeFileData> {
        self.file_data.iter().find(|f| f.ino == ino)
    }

    /// Get or create file data.
    fn get_or_create_file_data(&mut self, ino: u64) -> &mut TmpfsHugeFileData {
        if !self.file_data.iter().any(|f| f.ino == ino) {
            self.file_data.push(TmpfsHugeFileData {
                ino,
                data: Vec::new(),
            });
        }
        self.file_data.iter_mut().find(|f| f.ino == ino).unwrap()
    }

    /// Find mutable inode.
    fn find_inode_mut(&mut self, ino: u64) -> Result<&mut TmpfsHugeInode> {
        self.inodes
            .iter_mut()
            .find(|i| i.ino == ino)
            .ok_or(Error::NotFound)
    }
}

// ── InodeOps implementation ──────────────────────────────────────────────────

impl InodeOps for TmpfsHugeFs {
    fn lookup(&self, parent: &Inode, name: &str) -> Result<Inode> {
        let entry = self.find_dir_entry(parent.ino.0, name)?;
        let inode = self.find_inode(entry.ino)?;
        Ok(inode.to_vfs_inode())
    }

    fn create(&mut self, parent: &Inode, name: &str, mode: FileMode) -> Result<Inode> {
        if name.len() > MAX_NAME_LEN || name.is_empty() {
            return Err(Error::InvalidArgument);
        }
        if self.find_dir_entry(parent.ino.0, name).is_ok() {
            return Err(Error::AlreadyExists);
        }
        if self.dir_entry_count(parent.ino.0) >= MAX_DIR_ENTRIES {
            return Err(Error::OutOfMemory);
        }

        let ino = self.alloc_ino()?;
        let inode = TmpfsHugeInode::new_file(ino, mode.0);
        self.inodes.push(inode);

        self.dir_entries.push((
            parent.ino.0,
            TmpfsHugeDirEntry {
                ino,
                file_type: FileType::Regular,
                name: String::from(name),
            },
        ));

        let created = self.find_inode(ino)?;
        Ok(created.to_vfs_inode())
    }

    fn mkdir(&mut self, parent: &Inode, name: &str, mode: FileMode) -> Result<Inode> {
        if name.len() > MAX_NAME_LEN || name.is_empty() {
            return Err(Error::InvalidArgument);
        }
        if self.find_dir_entry(parent.ino.0, name).is_ok() {
            return Err(Error::AlreadyExists);
        }
        if self.dir_entry_count(parent.ino.0) >= MAX_DIR_ENTRIES {
            return Err(Error::OutOfMemory);
        }

        let ino = self.alloc_ino()?;
        let inode = TmpfsHugeInode::new_dir(ino, mode.0);
        self.inodes.push(inode);

        self.dir_entries.push((
            parent.ino.0,
            TmpfsHugeDirEntry {
                ino,
                file_type: FileType::Directory,
                name: String::from(name),
            },
        ));

        let created = self.find_inode(ino)?;
        Ok(created.to_vfs_inode())
    }

    fn unlink(&mut self, parent: &Inode, name: &str) -> Result<()> {
        let entry_ino = self.find_dir_entry(parent.ino.0, name)?.ino;
        let inode = self.find_inode(entry_ino)?;
        if inode.file_type == FileType::Directory {
            return Err(Error::InvalidArgument);
        }

        // Update stats for freed pages.
        let huge_count = inode.huge_page_count() as u64;
        let base_count = inode.base_page_count() as u64;

        let pos = self
            .dir_entries
            .iter()
            .position(|(p, e)| *p == parent.ino.0 && e.name == name)
            .ok_or(Error::NotFound)?;
        self.dir_entries.remove(pos);

        self.stats.huge_pages_allocated =
            self.stats.huge_pages_allocated.saturating_sub(huge_count);
        self.stats.base_pages_allocated =
            self.stats.base_pages_allocated.saturating_sub(base_count);

        self.inodes.retain(|i| i.ino != entry_ino);
        self.file_data.retain(|f| f.ino != entry_ino);
        Ok(())
    }

    fn rmdir(&mut self, parent: &Inode, name: &str) -> Result<()> {
        let entry_ino = self.find_dir_entry(parent.ino.0, name)?.ino;
        let inode = self.find_inode(entry_ino)?;
        if inode.file_type != FileType::Directory {
            return Err(Error::InvalidArgument);
        }
        if self.dir_entry_count(entry_ino) > 0 {
            return Err(Error::Busy);
        }

        let pos = self
            .dir_entries
            .iter()
            .position(|(p, e)| *p == parent.ino.0 && e.name == name)
            .ok_or(Error::NotFound)?;
        self.dir_entries.remove(pos);
        self.inodes.retain(|i| i.ino != entry_ino);
        Ok(())
    }

    fn read(&self, inode: &Inode, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let thp_inode = self.find_inode(inode.ino.0)?;
        if thp_inode.file_type != FileType::Regular {
            return Err(Error::InvalidArgument);
        }
        let fd = match self.get_file_data(inode.ino.0) {
            Some(fd) => fd,
            None => return Ok(0),
        };
        let start = offset as usize;
        if start >= fd.data.len() {
            return Ok(0);
        }
        let available = fd.data.len() - start;
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&fd.data[start..start + to_read]);
        Ok(to_read)
    }

    fn write(&mut self, inode: &Inode, offset: u64, data: &[u8]) -> Result<usize> {
        let thp_inode = self.find_inode(inode.ino.0)?;
        if thp_inode.file_type != FileType::Regular {
            return Err(Error::InvalidArgument);
        }
        let end = offset as usize + data.len();
        if end > self.opts.max_size {
            return Err(Error::OutOfMemory);
        }

        let ino = inode.ino.0;
        let fd = self.get_or_create_file_data(ino);
        if fd.data.len() < end {
            fd.data.resize(end, 0);
        }
        fd.data[offset as usize..end].copy_from_slice(data);

        let new_size = fd.data.len() as u64;

        // Allocate pages for the written region.
        let _ = self.allocate_pages(ino, offset as usize, data.len(), new_size);

        let inode_mut = self.find_inode_mut(ino)?;
        inode_mut.size = new_size;

        Ok(data.len())
    }

    fn truncate(&mut self, inode: &Inode, size: u64) -> Result<()> {
        let thp_inode = self.find_inode(inode.ino.0)?;
        if thp_inode.file_type != FileType::Regular {
            return Err(Error::InvalidArgument);
        }
        if size as usize > self.opts.max_size {
            return Err(Error::OutOfMemory);
        }

        let ino = inode.ino.0;
        let fd = self.get_or_create_file_data(ino);
        fd.data.resize(size as usize, 0);

        // Remove pages beyond the new size.
        let inode_idx = self
            .inodes
            .iter()
            .position(|i| i.ino == ino)
            .ok_or(Error::NotFound)?;

        let mut freed_huge = 0u64;
        let mut freed_base = 0u64;
        let new_size = size as usize;
        self.inodes[inode_idx].pages.retain(|p| {
            if p.offset >= new_size {
                match p.page_type {
                    PageType::Huge => freed_huge += 1,
                    PageType::Base => freed_base += 1,
                }
                false
            } else {
                true
            }
        });
        self.stats.huge_pages_allocated =
            self.stats.huge_pages_allocated.saturating_sub(freed_huge);
        self.stats.base_pages_allocated =
            self.stats.base_pages_allocated.saturating_sub(freed_base);

        self.inodes[inode_idx].size = size;
        Ok(())
    }
}
