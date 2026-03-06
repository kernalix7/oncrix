// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RAM filesystem — a simple in-memory filesystem for early boot.
//!
//! Ramfs stores all data in fixed-size memory buffers. It provides
//! a minimal but functional filesystem for the kernel's initial
//! root before a real filesystem is mounted.

use crate::inode::{FileMode, FileType, Inode, InodeNumber, InodeOps};
use oncrix_lib::{Error, Result};

/// Maximum number of inodes in ramfs.
const MAX_INODES: usize = 128;

/// Maximum file data size (4 KiB per file).
const MAX_FILE_SIZE: usize = 4096;

/// Maximum directory entries per directory.
const MAX_DIR_ENTRIES: usize = 32;

/// A directory entry in ramfs.
#[derive(Debug, Clone)]
struct RamDirEntry {
    /// Entry name.
    name: [u8; 256],
    /// Name length.
    name_len: usize,
    /// Child inode number.
    inode: InodeNumber,
}

/// Ramfs inode data — either file content or directory entries.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
enum RamInodeData {
    /// Regular file data.
    File {
        /// File content buffer.
        data: [u8; MAX_FILE_SIZE],
        /// Actual data length.
        len: usize,
    },
    /// Directory entries.
    Dir {
        /// Child entries.
        entries: [Option<RamDirEntry>; MAX_DIR_ENTRIES],
        /// Number of entries.
        count: usize,
    },
}

/// Ramfs filesystem.
pub struct Ramfs {
    /// Inode metadata.
    inodes: [Option<Inode>; MAX_INODES],
    /// Inode data (parallel array).
    data: [Option<RamInodeData>; MAX_INODES],
    /// Next inode number to allocate.
    next_ino: u64,
}

impl Default for Ramfs {
    fn default() -> Self {
        Self::new()
    }
}

impl Ramfs {
    /// Create a new ramfs with a root directory (inode 1).
    pub fn new() -> Self {
        const NONE_INODE: Option<Inode> = None;
        const NONE_DATA: Option<RamInodeData> = None;
        const NONE_ENTRY: Option<RamDirEntry> = None;

        let mut fs = Self {
            inodes: [NONE_INODE; MAX_INODES],
            data: [NONE_DATA; MAX_INODES],
            next_ino: 2,
        };

        // Create root directory at inode 1.
        let root_ino = InodeNumber(1);
        fs.inodes[0] = Some(Inode::new(
            root_ino,
            FileType::Directory,
            FileMode::DIR_DEFAULT,
        ));
        fs.data[0] = Some(RamInodeData::Dir {
            entries: [NONE_ENTRY; MAX_DIR_ENTRIES],
            count: 0,
        });

        fs
    }

    /// Return the root inode number.
    pub fn root_inode(&self) -> InodeNumber {
        InodeNumber(1)
    }

    /// Find the slot index for an inode number.
    fn slot_of(&self, ino: InodeNumber) -> Option<usize> {
        self.inodes
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|i| i.ino == ino))
    }

    /// Allocate a new inode number and slot.
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

    /// Add a directory entry to a directory.
    ///
    /// Returns `AlreadyExists` if a child with the same name already exists.
    fn add_dir_entry(
        &mut self,
        parent_slot: usize,
        name: &str,
        child_ino: InodeNumber,
    ) -> Result<()> {
        let data = self.data[parent_slot].as_mut().ok_or(Error::NotFound)?;
        if let RamInodeData::Dir { entries, count } = data {
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
                    *slot = Some(RamDirEntry {
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
}

impl InodeOps for Ramfs {
    fn lookup(&self, parent: &Inode, name: &str) -> Result<Inode> {
        let parent_slot = self.slot_of(parent.ino).ok_or(Error::NotFound)?;
        let data = self.data[parent_slot].as_ref().ok_or(Error::NotFound)?;

        if let RamInodeData::Dir { entries, .. } = data {
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
        self.data[child_slot] = Some(RamInodeData::File {
            data: [0u8; MAX_FILE_SIZE],
            len: 0,
        });
        self.add_dir_entry(parent_slot, name, child_ino)?;
        Ok(*self.inodes[child_slot].as_ref().ok_or(Error::NotFound)?)
    }

    fn mkdir(&mut self, parent: &Inode, name: &str, mode: FileMode) -> Result<Inode> {
        const NONE_ENTRY: Option<RamDirEntry> = None;
        let parent_slot = self.slot_of(parent.ino).ok_or(Error::NotFound)?;
        let (child_slot, child_ino) = self.alloc_inode(FileType::Directory, mode)?;
        self.data[child_slot] = Some(RamInodeData::Dir {
            entries: [NONE_ENTRY; MAX_DIR_ENTRIES],
            count: 0,
        });
        self.add_dir_entry(parent_slot, name, child_ino)?;
        Ok(*self.inodes[child_slot].as_ref().ok_or(Error::NotFound)?)
    }

    fn unlink(&mut self, parent: &Inode, name: &str) -> Result<()> {
        let parent_slot = self.slot_of(parent.ino).ok_or(Error::NotFound)?;

        // First, find the child inode to check its type.
        let child_ino = {
            let data = self.data[parent_slot].as_ref().ok_or(Error::NotFound)?;
            if let RamInodeData::Dir { entries, .. } = data {
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

        // POSIX: unlink must not remove directories (use rmdir).
        if let Some(slot) = self.slot_of(child_ino) {
            if let Some(inode) = &self.inodes[slot] {
                if inode.file_type == FileType::Directory {
                    return Err(Error::PermissionDenied);
                }
            }
        }

        // Remove the directory entry and free the inode.
        let data = self.data[parent_slot].as_mut().ok_or(Error::NotFound)?;
        if let RamInodeData::Dir { entries, count } = data {
            let name_bytes = name.as_bytes();
            for slot in entries.iter_mut() {
                if let Some(entry) = slot {
                    if &entry.name[..entry.name_len] == name_bytes {
                        let ino = entry.inode;
                        *slot = None;
                        *count -= 1;
                        if let Some(child_slot) = self.slot_of(ino) {
                            self.inodes[child_slot] = None;
                            self.data[child_slot] = None;
                        }
                        return Ok(());
                    }
                }
            }
        }
        Err(Error::NotFound)
    }

    fn rmdir(&mut self, parent: &Inode, name: &str) -> Result<()> {
        let parent_slot = self.slot_of(parent.ino).ok_or(Error::NotFound)?;

        // Find the child inode.
        let child_ino = {
            let data = self.data[parent_slot].as_ref().ok_or(Error::NotFound)?;
            if let RamInodeData::Dir { entries, .. } = data {
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

        // Verify the child is a directory.
        let child_slot = self.slot_of(child_ino).ok_or(Error::NotFound)?;
        if let Some(inode) = &self.inodes[child_slot] {
            if inode.file_type != FileType::Directory {
                return Err(Error::InvalidArgument);
            }
        }

        // POSIX: rmdir must fail if the directory is not empty.
        if let Some(RamInodeData::Dir { count, .. }) = &self.data[child_slot] {
            if *count > 0 {
                return Err(Error::InvalidArgument);
            }
        }

        // Remove the directory entry from parent and free child.
        let data = self.data[parent_slot].as_mut().ok_or(Error::NotFound)?;
        if let RamInodeData::Dir { entries, count } = data {
            let name_bytes = name.as_bytes();
            for slot in entries.iter_mut() {
                if let Some(entry) = slot {
                    if &entry.name[..entry.name_len] == name_bytes {
                        *slot = None;
                        *count -= 1;
                        self.inodes[child_slot] = None;
                        self.data[child_slot] = None;
                        return Ok(());
                    }
                }
            }
        }
        Err(Error::NotFound)
    }

    fn read(&self, inode: &Inode, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let slot = self.slot_of(inode.ino).ok_or(Error::NotFound)?;
        let data = self.data[slot].as_ref().ok_or(Error::NotFound)?;

        if let RamInodeData::File {
            data: file_data,
            len,
        } = data
        {
            let offset = offset as usize;
            if offset >= *len {
                return Ok(0);
            }
            let available = *len - offset;
            let to_read = buf.len().min(available);
            buf[..to_read].copy_from_slice(&file_data[offset..offset + to_read]);
            Ok(to_read)
        } else {
            Err(Error::InvalidArgument)
        }
    }

    fn write(&mut self, inode: &Inode, offset: u64, data: &[u8]) -> Result<usize> {
        let slot = self.slot_of(inode.ino).ok_or(Error::NotFound)?;
        let inode_data = self.data[slot].as_mut().ok_or(Error::NotFound)?;

        if let RamInodeData::File {
            data: file_data,
            len,
        } = inode_data
        {
            let offset = offset as usize;
            let end = offset + data.len();
            if end > MAX_FILE_SIZE {
                return Err(Error::OutOfMemory);
            }
            file_data[offset..end].copy_from_slice(data);
            if end > *len {
                *len = end;
            }

            // Update inode size.
            if let Some(inode_meta) = self.inodes[slot].as_mut() {
                inode_meta.size = *len as u64;
            }

            Ok(data.len())
        } else {
            Err(Error::InvalidArgument)
        }
    }

    fn truncate(&mut self, inode: &Inode, size: u64) -> Result<()> {
        let slot = self.slot_of(inode.ino).ok_or(Error::NotFound)?;
        let inode_data = self.data[slot].as_mut().ok_or(Error::NotFound)?;

        if let RamInodeData::File {
            data: file_data,
            len,
        } = inode_data
        {
            let new_len = (size as usize).min(MAX_FILE_SIZE);
            if new_len < *len {
                // Zero out truncated region.
                file_data[new_len..*len].fill(0);
            }
            *len = new_len;

            if let Some(inode_meta) = self.inodes[slot].as_mut() {
                inode_meta.size = new_len as u64;
            }
            Ok(())
        } else {
            Err(Error::InvalidArgument)
        }
    }
}
