// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Ramfs directory implementation.
//!
//! Provides a fixed-capacity in-memory directory for use with ramfs.
//! Each directory stores a flat list of `(name, inode_number)` entries.
//! This module implements create, lookup, remove, and iteration.

use oncrix_lib::{Error, Result};

/// Maximum number of entries per ramfs directory.
pub const RAMFS_DIR_MAX_ENTRIES: usize = 4096;

/// Maximum filename length.
pub const RAMFS_NAME_MAX: usize = 255;

/// Inode number type used in ramfs.
pub type RamfsIno = u64;

/// A single directory entry.
#[derive(Debug, Clone)]
pub struct RamfsDirEntry {
    /// Entry name (NUL-padded).
    pub name: [u8; RAMFS_NAME_MAX + 1],
    pub name_len: u8,
    /// Target inode number.
    pub ino: RamfsIno,
    /// Whether this slot is occupied.
    pub occupied: bool,
}

impl RamfsDirEntry {
    /// Create a new occupied entry.
    pub fn new(name: &[u8], ino: RamfsIno) -> Result<Self> {
        if name.len() > RAMFS_NAME_MAX || name.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; RAMFS_NAME_MAX + 1];
        buf[..name.len()].copy_from_slice(name);
        Ok(Self {
            name: buf,
            name_len: name.len() as u8,
            ino,
            occupied: true,
        })
    }

    /// Name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

/// In-memory ramfs directory.
pub struct RamfsDir {
    entries: [Option<RamfsDirEntry>; RAMFS_DIR_MAX_ENTRIES],
    count: usize,
    /// This directory's own inode number.
    pub ino: RamfsIno,
    /// Parent inode number.
    pub parent_ino: RamfsIno,
}

impl RamfsDir {
    /// Create a new empty directory.
    pub const fn new(ino: RamfsIno, parent_ino: RamfsIno) -> Self {
        Self {
            entries: [const { None }; RAMFS_DIR_MAX_ENTRIES],
            count: 0,
            ino,
            parent_ino,
        }
    }

    /// Add an entry to this directory.
    pub fn add(&mut self, name: &[u8], ino: RamfsIno) -> Result<()> {
        // Reject duplicate names.
        if self.lookup(name).is_some() {
            return Err(Error::AlreadyExists);
        }
        if self.count >= RAMFS_DIR_MAX_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let entry = RamfsDirEntry::new(name, ino)?;
        for slot in &mut self.entries {
            if slot.is_none() {
                *slot = Some(entry);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up an entry by name.
    pub fn lookup(&self, name: &[u8]) -> Option<RamfsIno> {
        // Handle "." and ".."
        if name == b"." {
            return Some(self.ino);
        }
        if name == b".." {
            return Some(self.parent_ino);
        }
        for slot in &self.entries {
            if let Some(entry) = slot.as_ref() {
                if entry.name_bytes() == name {
                    return Some(entry.ino);
                }
            }
        }
        None
    }

    /// Remove an entry by name.
    pub fn remove(&mut self, name: &[u8]) -> Result<RamfsIno> {
        for slot in &mut self.entries {
            if slot
                .as_ref()
                .map(|e| e.name_bytes() == name)
                .unwrap_or(false)
            {
                let ino = slot.as_ref().unwrap().ino;
                *slot = None;
                self.count -= 1;
                return Ok(ino);
            }
        }
        Err(Error::NotFound)
    }

    /// Rename an entry (change its name, keep the same inode).
    pub fn rename(&mut self, old_name: &[u8], new_name: &[u8]) -> Result<()> {
        if self.lookup(new_name).is_some() {
            return Err(Error::AlreadyExists);
        }
        for slot in &mut self.entries {
            if slot
                .as_ref()
                .map(|e| e.name_bytes() == old_name)
                .unwrap_or(false)
            {
                if let Some(entry) = slot.as_mut() {
                    if new_name.len() > RAMFS_NAME_MAX || new_name.is_empty() {
                        return Err(Error::InvalidArgument);
                    }
                    entry.name = [0u8; RAMFS_NAME_MAX + 1];
                    entry.name[..new_name.len()].copy_from_slice(new_name);
                    entry.name_len = new_name.len() as u8;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Number of real entries (excluding . and ..).
    pub fn count(&self) -> usize {
        self.count
    }

    /// Whether the directory is empty (no entries other than . and ..).
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterate over all directory entries.
    pub fn iter(&self) -> impl Iterator<Item = &RamfsDirEntry> {
        self.entries.iter().filter_map(|s| s.as_ref())
    }

    /// Fill a readdir buffer starting at cookie `offset`.
    ///
    /// Returns `(entries_written, next_cookie)`.  Cookie 0/1/2 are reserved
    /// for ".", "..", and real entries start at 3.
    pub fn readdir(&self, offset: u64, out: &mut [(RamfsIno, &str)]) -> (usize, u64) {
        let _ = out; // Placeholder — real impl writes into a user buffer.
        let _ = offset;
        (0, u64::MAX)
    }
}
