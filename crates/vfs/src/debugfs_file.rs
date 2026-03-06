// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! debugfs file operations.
//!
//! debugfs is a simple in-memory filesystem mounted at `/sys/kernel/debug/`
//! (or `/debug/`). It exposes kernel internals for debugging purposes.
//!
//! This module provides:
//! - [`DebugfsEntry`] — an entry (file, directory, or symlink) in debugfs
//! - Create/remove operations
//! - Simple scalar read/write helpers (u8, u16, u32, u64, bool, blob)
//! - Directory lookup
//!
//! # References
//!
//! - Linux `fs/debugfs/file.c`, `fs/debugfs/inode.c`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum entries in the debugfs table.
pub const MAX_DEBUGFS_ENTRIES: usize = 512;

/// Maximum entry name length.
pub const MAX_ENTRY_NAME: usize = 128;

/// Maximum blob data size per entry.
pub const MAX_BLOB_SIZE: usize = 4096;

/// Inode numbers start here.
pub const DEBUGFS_INO_BASE: u64 = 0xD0000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Type of a debugfs entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugfsEntryType {
    /// Regular file.
    File,
    /// Directory.
    Dir,
    /// Symbolic link.
    Symlink,
}

/// Data payload for a debugfs file.
#[derive(Clone)]
pub enum DebugfsData {
    /// Unsigned 8-bit value.
    U8(u8),
    /// Unsigned 16-bit value.
    U16(u16),
    /// Unsigned 32-bit value.
    U32(u32),
    /// Unsigned 64-bit value.
    U64(u64),
    /// Boolean value.
    Bool(bool),
    /// Raw blob data.
    Blob([u8; MAX_BLOB_SIZE], usize),
    /// No data (directory or unset).
    None,
}

/// A debugfs entry (file, directory, or symlink).
#[derive(Clone)]
pub struct DebugfsEntry {
    /// Entry name.
    pub name: [u8; MAX_ENTRY_NAME],
    /// Name length.
    pub name_len: usize,
    /// File mode.
    pub mode: u32,
    /// Parent inode (0 = root).
    pub parent_ino: u64,
    /// This entry's inode.
    pub ino: u64,
    /// Entry type.
    pub entry_type: DebugfsEntryType,
    /// Data (only meaningful for File entries).
    pub data: DebugfsData,
    /// Symlink target (only for Symlink entries).
    pub target: [u8; MAX_ENTRY_NAME],
    /// Target length.
    pub target_len: usize,
    /// Slot in use.
    pub in_use: bool,
}

impl DebugfsEntry {
    fn empty() -> Self {
        Self {
            name: [0u8; MAX_ENTRY_NAME],
            name_len: 0,
            mode: 0o444,
            parent_ino: 0,
            ino: 0,
            entry_type: DebugfsEntryType::File,
            data: DebugfsData::None,
            target: [0u8; MAX_ENTRY_NAME],
            target_len: 0,
            in_use: false,
        }
    }

    /// Return entry name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// The debugfs table.
pub struct DebugfsTable {
    entries: [DebugfsEntry; MAX_DEBUGFS_ENTRIES],
    count: usize,
    next_ino: u64,
}

impl DebugfsTable {
    /// Create an empty debugfs table.
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| DebugfsEntry::empty()),
            count: 0,
            next_ino: DEBUGFS_INO_BASE + 1,
        }
    }

    fn find(&self, parent_ino: u64, name: &[u8]) -> Option<usize> {
        for i in 0..MAX_DEBUGFS_ENTRIES {
            if self.entries[i].in_use
                && self.entries[i].parent_ino == parent_ino
                && self.entries[i].name_bytes() == name
            {
                return Some(i);
            }
        }
        None
    }

    fn find_by_ino(&self, ino: u64) -> Option<usize> {
        for i in 0..MAX_DEBUGFS_ENTRIES {
            if self.entries[i].in_use && self.entries[i].ino == ino {
                return Some(i);
            }
        }
        None
    }

    fn free_slot(&self) -> Option<usize> {
        for i in 0..MAX_DEBUGFS_ENTRIES {
            if !self.entries[i].in_use {
                return Some(i);
            }
        }
        None
    }

    fn alloc_ino(&mut self) -> u64 {
        let ino = self.next_ino;
        self.next_ino += 1;
        ino
    }
}

impl Default for DebugfsTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Create a debugfs file entry.
///
/// Returns the inode number of the new entry.
pub fn debugfs_create_file(
    table: &mut DebugfsTable,
    name: &[u8],
    mode: u32,
    parent_ino: u64,
    data: DebugfsData,
) -> Result<u64> {
    if name.is_empty() || name.len() > MAX_ENTRY_NAME {
        return Err(Error::InvalidArgument);
    }
    if table.find(parent_ino, name).is_some() {
        return Err(Error::AlreadyExists);
    }
    let slot = table.free_slot().ok_or(Error::OutOfMemory)?;
    let ino = table.alloc_ino();
    let mut entry = DebugfsEntry::empty();
    entry.name[..name.len()].copy_from_slice(name);
    entry.name_len = name.len();
    entry.mode = mode;
    entry.parent_ino = parent_ino;
    entry.ino = ino;
    entry.entry_type = DebugfsEntryType::File;
    entry.data = data;
    entry.in_use = true;
    table.entries[slot] = entry;
    table.count += 1;
    Ok(ino)
}

/// Create a debugfs directory.
///
/// Returns the inode number of the new directory.
pub fn debugfs_create_dir(table: &mut DebugfsTable, name: &[u8], parent_ino: u64) -> Result<u64> {
    if name.is_empty() || name.len() > MAX_ENTRY_NAME {
        return Err(Error::InvalidArgument);
    }
    if table.find(parent_ino, name).is_some() {
        return Err(Error::AlreadyExists);
    }
    let slot = table.free_slot().ok_or(Error::OutOfMemory)?;
    let ino = table.alloc_ino();
    let mut entry = DebugfsEntry::empty();
    entry.name[..name.len()].copy_from_slice(name);
    entry.name_len = name.len();
    entry.mode = 0o755;
    entry.parent_ino = parent_ino;
    entry.ino = ino;
    entry.entry_type = DebugfsEntryType::Dir;
    entry.in_use = true;
    table.entries[slot] = entry;
    table.count += 1;
    Ok(ino)
}

/// Create a debugfs symlink.
///
/// Returns the inode number of the new symlink.
pub fn debugfs_create_symlink(
    table: &mut DebugfsTable,
    name: &[u8],
    parent_ino: u64,
    target: &[u8],
) -> Result<u64> {
    if name.is_empty() || name.len() > MAX_ENTRY_NAME {
        return Err(Error::InvalidArgument);
    }
    if target.len() > MAX_ENTRY_NAME {
        return Err(Error::InvalidArgument);
    }
    if table.find(parent_ino, name).is_some() {
        return Err(Error::AlreadyExists);
    }
    let slot = table.free_slot().ok_or(Error::OutOfMemory)?;
    let ino = table.alloc_ino();
    let mut entry = DebugfsEntry::empty();
    entry.name[..name.len()].copy_from_slice(name);
    entry.name_len = name.len();
    entry.mode = 0o777;
    entry.parent_ino = parent_ino;
    entry.ino = ino;
    entry.entry_type = DebugfsEntryType::Symlink;
    entry.target[..target.len()].copy_from_slice(target);
    entry.target_len = target.len();
    entry.in_use = true;
    table.entries[slot] = entry;
    table.count += 1;
    Ok(ino)
}

/// Remove a debugfs entry by inode number.
pub fn debugfs_remove(table: &mut DebugfsTable, ino: u64) -> Result<()> {
    let slot = table.find_by_ino(ino).ok_or(Error::NotFound)?;
    table.entries[slot] = DebugfsEntry::empty();
    table.count = table.count.saturating_sub(1);
    Ok(())
}

/// Look up an entry by parent inode and name.
pub fn debugfs_lookup<'a>(
    table: &'a DebugfsTable,
    parent_ino: u64,
    name: &[u8],
) -> Option<&'a DebugfsEntry> {
    let slot = table.find(parent_ino, name)?;
    Some(&table.entries[slot])
}

/// Read a u64 value from a debugfs file.
pub fn debugfs_read_u64(table: &DebugfsTable, ino: u64) -> Result<u64> {
    let slot = table.find_by_ino(ino).ok_or(Error::NotFound)?;
    match table.entries[slot].data {
        DebugfsData::U64(v) => Ok(v),
        DebugfsData::U32(v) => Ok(v as u64),
        DebugfsData::U16(v) => Ok(v as u64),
        DebugfsData::U8(v) => Ok(v as u64),
        DebugfsData::Bool(v) => Ok(v as u64),
        _ => Err(Error::InvalidArgument),
    }
}

/// Write a u64 value to a debugfs file.
pub fn debugfs_write_u64(table: &mut DebugfsTable, ino: u64, val: u64) -> Result<()> {
    let slot = table.find_by_ino(ino).ok_or(Error::NotFound)?;
    table.entries[slot].data = DebugfsData::U64(val);
    Ok(())
}

/// Read blob data from a debugfs file into `out`.
///
/// Returns bytes copied.
pub fn debugfs_read_blob(
    table: &DebugfsTable,
    ino: u64,
    offset: usize,
    out: &mut [u8],
) -> Result<usize> {
    let slot = table.find_by_ino(ino).ok_or(Error::NotFound)?;
    match table.entries[slot].data {
        DebugfsData::Blob(ref data, len) => {
            if offset >= len {
                return Ok(0);
            }
            let copy = (len - offset).min(out.len());
            out[..copy].copy_from_slice(&data[offset..offset + copy]);
            Ok(copy)
        }
        _ => Err(Error::InvalidArgument),
    }
}

/// Write blob data to a debugfs file.
pub fn debugfs_write_blob(table: &mut DebugfsTable, ino: u64, data: &[u8]) -> Result<()> {
    if data.len() > MAX_BLOB_SIZE {
        return Err(Error::InvalidArgument);
    }
    let slot = table.find_by_ino(ino).ok_or(Error::NotFound)?;
    let mut buf = [0u8; MAX_BLOB_SIZE];
    buf[..data.len()].copy_from_slice(data);
    table.entries[slot].data = DebugfsData::Blob(buf, data.len());
    Ok(())
}

/// List all entries under `parent_ino` into `out`.
///
/// Each element is `(ino, entry_type, name_buf, name_len)`.
/// Returns count written.
pub fn debugfs_readdir(
    table: &DebugfsTable,
    parent_ino: u64,
    out: &mut [(u64, DebugfsEntryType, [u8; MAX_ENTRY_NAME], usize)],
) -> usize {
    let mut written = 0;
    for i in 0..MAX_DEBUGFS_ENTRIES {
        if written >= out.len() {
            break;
        }
        if table.entries[i].in_use && table.entries[i].parent_ino == parent_ino {
            out[written] = (
                table.entries[i].ino,
                table.entries[i].entry_type,
                table.entries[i].name,
                table.entries[i].name_len,
            );
            written += 1;
        }
    }
    written
}
