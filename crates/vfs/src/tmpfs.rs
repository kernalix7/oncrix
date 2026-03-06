// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! tmpfs — temporary filesystem backed by memory pages.
//!
//! Unlike [`Ramfs`](crate::ramfs) which stores each file in a single
//! 4 KiB buffer, tmpfs uses page-based storage where each file can
//! span multiple 4 KiB pages, supporting files up to 64 KiB.
//!
//! tmpfs is mounted at `/tmp` and all data is volatile — lost on
//! reboot. It is the standard POSIX-like tmpfs for user-space
//! temporary files.
//!
//! Reference: Linux `mm/shmem.c`, POSIX.1-2024 §tmpfs.

use crate::inode::{FileMode, FileType, Inode, InodeNumber, InodeOps};
use oncrix_lib::{Error, Result};

/// Page size (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Maximum pages per file (16 pages = 64 KiB per file).
const MAX_PAGES_PER_FILE: usize = 16;

/// Maximum number of inodes.
const MAX_INODES: usize = 256;

/// Maximum directory entries per directory.
const MAX_DIR_ENTRIES: usize = 64;

/// Total page pool size.
/// Each page is 4 KiB, so 512 pages = 2 MiB total.
const PAGE_POOL_SIZE: usize = 512;

/// A single page of file data.
#[derive(Clone, Copy)]
struct Page {
    data: [u8; PAGE_SIZE],
}

impl Page {
    const fn zeroed() -> Self {
        Self {
            data: [0u8; PAGE_SIZE],
        }
    }
}

/// A directory entry in tmpfs.
#[derive(Debug, Clone)]
struct TmpDirEntry {
    /// Entry name.
    name: [u8; 256],
    /// Name length.
    name_len: usize,
    /// Child inode number.
    inode: InodeNumber,
}

/// Per-inode data — either file pages or directory entries.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
enum TmpInodeData {
    /// Regular file: page indices into the global page pool.
    /// `pages[i]` holds the pool index for the i-th page of the file.
    /// `None` means the page is not allocated (sparse/hole).
    File {
        /// Page pool indices for this file's pages.
        pages: [Option<usize>; MAX_PAGES_PER_FILE],
        /// File length in bytes.
        len: usize,
    },
    /// Directory entries.
    Dir {
        /// Child entries.
        entries: [Option<TmpDirEntry>; MAX_DIR_ENTRIES],
        /// Number of entries.
        count: usize,
    },
}

impl core::fmt::Debug for Page {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Page([..4096])")
    }
}

/// Tmpfs filesystem.
///
/// Uses a global page pool for file data storage. Pages are
/// allocated on write and freed on unlink/truncate.
pub struct Tmpfs {
    /// Inode metadata.
    inodes: [Option<Inode>; MAX_INODES],
    /// Per-inode data (parallel array).
    data: [Option<TmpInodeData>; MAX_INODES],
    /// Global page pool.
    pages: [Option<Page>; PAGE_POOL_SIZE],
    /// Page allocation bitmap (true = in use).
    page_used: [bool; PAGE_POOL_SIZE],
    /// Next inode number to allocate.
    next_ino: u64,
    /// Number of pages currently allocated.
    pages_used_count: usize,
}

impl Default for Tmpfs {
    fn default() -> Self {
        Self::new()
    }
}

impl Tmpfs {
    /// Create a new tmpfs with a root directory (inode 1).
    pub fn new() -> Self {
        const NONE_INODE: Option<Inode> = None;
        const NONE_DATA: Option<TmpInodeData> = None;
        const NONE_PAGE: Option<Page> = None;
        const NONE_ENTRY: Option<TmpDirEntry> = None;

        let mut fs = Self {
            inodes: [NONE_INODE; MAX_INODES],
            data: [NONE_DATA; MAX_INODES],
            pages: [NONE_PAGE; PAGE_POOL_SIZE],
            page_used: [false; PAGE_POOL_SIZE],
            next_ino: 2,
            pages_used_count: 0,
        };

        // Create root directory at inode 1.
        let root_ino = InodeNumber(1);
        fs.inodes[0] = Some(Inode::new(
            root_ino,
            FileType::Directory,
            FileMode::DIR_DEFAULT,
        ));
        fs.data[0] = Some(TmpInodeData::Dir {
            entries: [NONE_ENTRY; MAX_DIR_ENTRIES],
            count: 0,
        });

        fs
    }

    /// Return the root inode number.
    pub fn root_inode(&self) -> InodeNumber {
        InodeNumber(1)
    }

    /// Return total capacity in bytes.
    pub fn capacity(&self) -> usize {
        PAGE_POOL_SIZE * PAGE_SIZE
    }

    /// Return used bytes (pages allocated × page size).
    pub fn used(&self) -> usize {
        self.pages_used_count * PAGE_SIZE
    }

    /// Return free bytes.
    pub fn free(&self) -> usize {
        self.capacity() - self.used()
    }

    /// Find the slot index for an inode number.
    fn slot_of(&self, ino: InodeNumber) -> Option<usize> {
        self.inodes
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|i| i.ino == ino))
    }

    /// Allocate a new inode.
    fn alloc_inode(&mut self, file_type: FileType, mode: FileMode) -> Result<(usize, InodeNumber)> {
        let ino = InodeNumber(self.next_ino);
        self.next_ino += 1;

        for (idx, slot) in self.inodes.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(Inode::new(ino, file_type, mode));
                return Ok((idx, ino));
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Allocate a page from the pool.
    fn alloc_page(&mut self) -> Result<usize> {
        for (idx, used) in self.page_used.iter_mut().enumerate() {
            if !*used {
                *used = true;
                self.pages[idx] = Some(Page::zeroed());
                self.pages_used_count += 1;
                return Ok(idx);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Free a page back to the pool.
    fn free_page(&mut self, idx: usize) {
        if idx < PAGE_POOL_SIZE && self.page_used[idx] {
            self.page_used[idx] = false;
            self.pages[idx] = None;
            self.pages_used_count = self.pages_used_count.saturating_sub(1);
        }
    }

    /// Free all pages belonging to a file inode.
    fn free_file_pages(&mut self, slot: usize) {
        if let Some(TmpInodeData::File { pages, .. }) = &self.data[slot] {
            // Collect page indices to free.
            let to_free: [Option<usize>; MAX_PAGES_PER_FILE] = *pages;
            for page_idx in to_free.into_iter().flatten() {
                self.free_page(page_idx);
            }
        }
    }

    /// Add a directory entry.
    fn add_dir_entry(
        &mut self,
        parent_slot: usize,
        name: &str,
        child_ino: InodeNumber,
    ) -> Result<()> {
        let data = self.data[parent_slot].as_mut().ok_or(Error::NotFound)?;
        if let TmpInodeData::Dir { entries, count } = data {
            if *count >= MAX_DIR_ENTRIES {
                return Err(Error::OutOfMemory);
            }
            let name_bytes = name.as_bytes();
            if name_bytes.len() > 255 {
                return Err(Error::InvalidArgument);
            }

            // Check for duplicate names.
            for existing in entries.iter().flatten() {
                if &existing.name[..existing.name_len] == name_bytes {
                    return Err(Error::AlreadyExists);
                }
            }

            let mut entry_name = [0u8; 256];
            entry_name[..name_bytes.len()].copy_from_slice(name_bytes);

            for slot in entries.iter_mut() {
                if slot.is_none() {
                    *slot = Some(TmpDirEntry {
                        name: entry_name,
                        name_len: name_bytes.len(),
                        inode: child_ino,
                    });
                    *count += 1;
                    return Ok(());
                }
            }
            Err(Error::OutOfMemory)
        } else {
            Err(Error::InvalidArgument)
        }
    }

    /// Remove a directory entry by name, returning the child inode number.
    fn remove_dir_entry(&mut self, parent_slot: usize, name: &str) -> Result<InodeNumber> {
        let data = self.data[parent_slot].as_mut().ok_or(Error::NotFound)?;
        if let TmpInodeData::Dir { entries, count } = data {
            let name_bytes = name.as_bytes();
            for slot in entries.iter_mut() {
                if let Some(entry) = slot {
                    if &entry.name[..entry.name_len] == name_bytes {
                        let ino = entry.inode;
                        *slot = None;
                        *count -= 1;
                        return Ok(ino);
                    }
                }
            }
            Err(Error::NotFound)
        } else {
            Err(Error::InvalidArgument)
        }
    }
}

impl InodeOps for Tmpfs {
    fn lookup(&self, parent: &Inode, name: &str) -> Result<Inode> {
        let parent_slot = self.slot_of(parent.ino).ok_or(Error::NotFound)?;
        let data = self.data[parent_slot].as_ref().ok_or(Error::NotFound)?;

        if let TmpInodeData::Dir { entries, .. } = data {
            let name_bytes = name.as_bytes();
            for entry in entries.iter().flatten() {
                if &entry.name[..entry.name_len] == name_bytes {
                    let child_slot = self.slot_of(entry.inode).ok_or(Error::NotFound)?;
                    return self.inodes[child_slot]
                        .as_ref()
                        .copied()
                        .ok_or(Error::NotFound);
                }
            }
            Err(Error::NotFound)
        } else {
            Err(Error::InvalidArgument)
        }
    }

    fn create(&mut self, parent: &Inode, name: &str, mode: FileMode) -> Result<Inode> {
        let parent_slot = self.slot_of(parent.ino).ok_or(Error::NotFound)?;
        let (child_slot, child_ino) = self.alloc_inode(FileType::Regular, mode)?;

        self.data[child_slot] = Some(TmpInodeData::File {
            pages: [None; MAX_PAGES_PER_FILE],
            len: 0,
        });

        if let Err(e) = self.add_dir_entry(parent_slot, name, child_ino) {
            // Roll back inode allocation on directory entry failure.
            self.inodes[child_slot] = None;
            self.data[child_slot] = None;
            return Err(e);
        }

        Ok(*self.inodes[child_slot].as_ref().ok_or(Error::NotFound)?)
    }

    fn mkdir(&mut self, parent: &Inode, name: &str, mode: FileMode) -> Result<Inode> {
        const NONE_ENTRY: Option<TmpDirEntry> = None;
        let parent_slot = self.slot_of(parent.ino).ok_or(Error::NotFound)?;
        let (child_slot, child_ino) = self.alloc_inode(FileType::Directory, mode)?;

        self.data[child_slot] = Some(TmpInodeData::Dir {
            entries: [NONE_ENTRY; MAX_DIR_ENTRIES],
            count: 0,
        });

        if let Err(e) = self.add_dir_entry(parent_slot, name, child_ino) {
            self.inodes[child_slot] = None;
            self.data[child_slot] = None;
            return Err(e);
        }

        Ok(*self.inodes[child_slot].as_ref().ok_or(Error::NotFound)?)
    }

    fn unlink(&mut self, parent: &Inode, name: &str) -> Result<()> {
        let parent_slot = self.slot_of(parent.ino).ok_or(Error::NotFound)?;

        // Look up child to verify it's not a directory.
        let child_ino = {
            let data = self.data[parent_slot].as_ref().ok_or(Error::NotFound)?;
            if let TmpInodeData::Dir { entries, .. } = data {
                let name_bytes = name.as_bytes();
                let entry = entries
                    .iter()
                    .flatten()
                    .find(|e| &e.name[..e.name_len] == name_bytes)
                    .ok_or(Error::NotFound)?;
                entry.inode
            } else {
                return Err(Error::InvalidArgument);
            }
        };

        let child_slot = self.slot_of(child_ino).ok_or(Error::NotFound)?;
        if let Some(inode) = &self.inodes[child_slot] {
            if inode.file_type == FileType::Directory {
                return Err(Error::PermissionDenied);
            }
        }

        // Free file pages, then remove entry and inode.
        self.free_file_pages(child_slot);
        self.remove_dir_entry(parent_slot, name)?;
        self.inodes[child_slot] = None;
        self.data[child_slot] = None;
        Ok(())
    }

    fn rmdir(&mut self, parent: &Inode, name: &str) -> Result<()> {
        let parent_slot = self.slot_of(parent.ino).ok_or(Error::NotFound)?;

        // Look up child.
        let child_ino = {
            let data = self.data[parent_slot].as_ref().ok_or(Error::NotFound)?;
            if let TmpInodeData::Dir { entries, .. } = data {
                let name_bytes = name.as_bytes();
                let entry = entries
                    .iter()
                    .flatten()
                    .find(|e| &e.name[..e.name_len] == name_bytes)
                    .ok_or(Error::NotFound)?;
                entry.inode
            } else {
                return Err(Error::InvalidArgument);
            }
        };

        let child_slot = self.slot_of(child_ino).ok_or(Error::NotFound)?;

        // Must be a directory.
        if let Some(inode) = &self.inodes[child_slot] {
            if inode.file_type != FileType::Directory {
                return Err(Error::InvalidArgument);
            }
        }

        // Must be empty.
        if let Some(TmpInodeData::Dir { count, .. }) = &self.data[child_slot] {
            if *count > 0 {
                return Err(Error::InvalidArgument);
            }
        }

        self.remove_dir_entry(parent_slot, name)?;
        self.inodes[child_slot] = None;
        self.data[child_slot] = None;
        Ok(())
    }

    fn read(&self, inode: &Inode, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let slot = self.slot_of(inode.ino).ok_or(Error::NotFound)?;
        let data = self.data[slot].as_ref().ok_or(Error::NotFound)?;

        if let TmpInodeData::File { pages, len } = data {
            let offset = offset as usize;
            if offset >= *len {
                return Ok(0);
            }
            let available = *len - offset;
            let to_read = buf.len().min(available);

            let mut bytes_read = 0;
            let mut file_pos = offset;

            while bytes_read < to_read {
                let page_idx = file_pos / PAGE_SIZE;
                let page_off = file_pos % PAGE_SIZE;
                let chunk = (PAGE_SIZE - page_off).min(to_read - bytes_read);

                if let Some(pool_idx) = pages[page_idx] {
                    if let Some(page) = &self.pages[pool_idx] {
                        buf[bytes_read..bytes_read + chunk]
                            .copy_from_slice(&page.data[page_off..page_off + chunk]);
                    } else {
                        // Sparse hole — read as zeros.
                        buf[bytes_read..bytes_read + chunk].fill(0);
                    }
                } else {
                    // No page allocated — sparse hole.
                    buf[bytes_read..bytes_read + chunk].fill(0);
                }

                bytes_read += chunk;
                file_pos += chunk;
            }

            Ok(bytes_read)
        } else {
            Err(Error::InvalidArgument)
        }
    }

    fn write(&mut self, inode: &Inode, offset: u64, data: &[u8]) -> Result<usize> {
        let slot = self.slot_of(inode.ino).ok_or(Error::NotFound)?;

        let offset = offset as usize;
        let end = offset + data.len();
        let max_size = MAX_PAGES_PER_FILE * PAGE_SIZE;
        if end > max_size {
            return Err(Error::OutOfMemory);
        }

        let mut bytes_written = 0;
        let mut file_pos = offset;

        while bytes_written < data.len() {
            let page_idx = file_pos / PAGE_SIZE;
            let page_off = file_pos % PAGE_SIZE;
            let chunk = (PAGE_SIZE - page_off).min(data.len() - bytes_written);

            // Get or allocate the page.
            let pool_idx = {
                let inode_data = self.data[slot].as_ref().ok_or(Error::NotFound)?;
                if let TmpInodeData::File { pages, .. } = inode_data {
                    pages[page_idx]
                } else {
                    return Err(Error::InvalidArgument);
                }
            };

            let pool_idx = match pool_idx {
                Some(idx) => idx,
                None => {
                    let idx = self.alloc_page()?;
                    if let Some(TmpInodeData::File { pages, .. }) = &mut self.data[slot] {
                        pages[page_idx] = Some(idx);
                    }
                    idx
                }
            };

            // Write data to the page.
            if let Some(page) = &mut self.pages[pool_idx] {
                page.data[page_off..page_off + chunk]
                    .copy_from_slice(&data[bytes_written..bytes_written + chunk]);
            }

            bytes_written += chunk;
            file_pos += chunk;
        }

        // Update file length.
        if let Some(TmpInodeData::File { len, .. }) = &mut self.data[slot] {
            if end > *len {
                *len = end;
            }
        }

        // Update inode size.
        if let Some(inode_meta) = self.inodes[slot].as_mut() {
            if let Some(TmpInodeData::File { len, .. }) = &self.data[slot] {
                inode_meta.size = *len as u64;
            }
        }

        Ok(bytes_written)
    }

    fn truncate(&mut self, inode: &Inode, size: u64) -> Result<()> {
        let slot = self.slot_of(inode.ino).ok_or(Error::NotFound)?;
        let max_size = MAX_PAGES_PER_FILE * PAGE_SIZE;
        let new_len = (size as usize).min(max_size);

        // Free pages beyond the new size.
        let new_page_count = new_len.div_ceil(PAGE_SIZE);

        if let Some(TmpInodeData::File { pages, len }) = &mut self.data[slot] {
            // Free pages that are no longer needed.
            for page_entry in pages.iter_mut().skip(new_page_count) {
                if let Some(pool_idx) = page_entry.take() {
                    self.page_used[pool_idx] = false;
                    self.pages[pool_idx] = None;
                    self.pages_used_count = self.pages_used_count.saturating_sub(1);
                }
            }

            // Zero out the partial last page if truncating down.
            if new_len < *len && new_page_count > 0 {
                let last_page_off = new_len % PAGE_SIZE;
                if last_page_off > 0 {
                    if let Some(pool_idx) = pages[new_page_count - 1] {
                        if let Some(page) = &mut self.pages[pool_idx] {
                            page.data[last_page_off..].fill(0);
                        }
                    }
                }
            }

            *len = new_len;
        } else {
            return Err(Error::InvalidArgument);
        }

        if let Some(inode_meta) = self.inodes[slot].as_mut() {
            inode_meta.size = new_len as u64;
        }

        Ok(())
    }
}

impl core::fmt::Debug for Tmpfs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tmpfs")
            .field(
                "inodes_used",
                &self.inodes.iter().filter(|i| i.is_some()).count(),
            )
            .field("pages_used", &self.pages_used_count)
            .field("capacity_bytes", &self.capacity())
            .finish()
    }
}
