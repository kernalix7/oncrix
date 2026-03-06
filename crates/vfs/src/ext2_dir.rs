// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ext2 directory operations.
//!
//! Implements the ext2 directory entry format and operations:
//!
//! - [`Ext2DirEntry`] — on-disk directory entry with inode, name, type
//! - `ext2_readdir` — iterate directory entries from a block buffer
//! - `ext2_lookup` — find an entry by name in a directory block
//! - `ext2_add_entry` — append a new entry to a directory block
//! - `ext2_remove_entry` — logically delete an entry (merge with prev)
//!
//! # Directory Format
//!
//! ext2 directories are stored as a variable-length linked list within
//! each 4096-byte block. Each entry has:
//! - `inode` (4 bytes) — 0 means deleted/empty
//! - `rec_len` (2 bytes) — length of this record (for next-entry skip)
//! - `name_len` (1 byte) — actual name length
//! - `file_type` (1 byte) — EXT2_FT_* type
//! - `name[255]` — name, not NUL-terminated
//!
//! # Reference
//!
//! Linux `fs/ext2/dir.c`, ext2 disk layout specification.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Directory block size.
const DIR_BLOCK_SIZE: usize = 4096;

/// Minimum record length (fixed header + 1 name byte, aligned to 4).
const MIN_REC_LEN: usize = 12;

/// Maximum name length.
const MAX_NAME_LEN: usize = 255;

/// Maximum entries returnable from readdir.
const MAX_READDIR_ENTRIES: usize = 256;

/// Record length alignment.
const REC_LEN_ALIGN: usize = 4;

// ---------------------------------------------------------------------------
// File type codes
// ---------------------------------------------------------------------------

/// Unknown file type.
pub const EXT2_FT_UNKNOWN: u8 = 0;
/// Regular file.
pub const EXT2_FT_REG_FILE: u8 = 1;
/// Directory.
pub const EXT2_FT_DIR: u8 = 2;
/// Character device.
pub const EXT2_FT_CHRDEV: u8 = 3;
/// Block device.
pub const EXT2_FT_BLKDEV: u8 = 4;
/// FIFO.
pub const EXT2_FT_FIFO: u8 = 5;
/// Socket.
pub const EXT2_FT_SOCK: u8 = 6;
/// Symbolic link.
pub const EXT2_FT_SYMLINK: u8 = 7;

// ---------------------------------------------------------------------------
// In-memory directory entry
// ---------------------------------------------------------------------------

/// An ext2 directory entry.
#[derive(Debug, Clone)]
pub struct Ext2DirEntry {
    /// Inode number (0 = deleted/empty).
    pub inode: u32,
    /// Record length (distance to next entry).
    pub rec_len: u16,
    /// Name length.
    pub name_len: u8,
    /// File type.
    pub file_type: u8,
    /// Entry name.
    pub name: [u8; MAX_NAME_LEN],
}

impl Ext2DirEntry {
    /// Creates a new directory entry.
    pub fn new(inode: u32, name: &[u8], file_type: u8) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; MAX_NAME_LEN];
        buf[..name.len()].copy_from_slice(name);
        let rec_len = Self::needed_rec_len(name.len());
        Ok(Self {
            inode,
            rec_len: rec_len as u16,
            name_len: name.len() as u8,
            file_type,
            name: buf,
        })
    }

    /// Returns the name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Returns whether this entry is active (inode != 0).
    pub fn is_active(&self) -> bool {
        self.inode != 0
    }

    /// Returns the record length required to store a name of `name_len` bytes.
    pub fn needed_rec_len(name_len: usize) -> usize {
        let base = 8 + name_len; // header (8 bytes) + name
        (base + REC_LEN_ALIGN - 1) & !(REC_LEN_ALIGN - 1)
    }

    /// Returns the actual used space of this entry.
    pub fn actual_len(&self) -> usize {
        Self::needed_rec_len(self.name_len as usize)
    }

    /// Returns the slack space in this record.
    pub fn slack(&self) -> usize {
        self.rec_len as usize - self.actual_len()
    }
}

// ---------------------------------------------------------------------------
// Block buffer abstraction
// ---------------------------------------------------------------------------

/// An in-memory directory block (4096 bytes).
pub struct DirBlock {
    /// Raw block data.
    data: [u8; DIR_BLOCK_SIZE],
    /// Whether the block has been modified.
    dirty: bool,
}

impl DirBlock {
    /// Creates an empty directory block.
    pub fn new() -> Self {
        Self {
            data: [0u8; DIR_BLOCK_SIZE],
            dirty: false,
        }
    }

    /// Creates a directory block from existing data.
    pub fn from_data(data: [u8; DIR_BLOCK_SIZE]) -> Self {
        Self { data, dirty: false }
    }

    /// Returns the raw block data.
    pub fn data(&self) -> &[u8; DIR_BLOCK_SIZE] {
        &self.data
    }

    /// Returns whether the block has been modified.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Reads a u32 little-endian from offset.
    fn read_u32(&self, off: usize) -> u32 {
        u32::from_le_bytes([
            self.data[off],
            self.data[off + 1],
            self.data[off + 2],
            self.data[off + 3],
        ])
    }

    /// Reads a u16 little-endian from offset.
    fn read_u16(&self, off: usize) -> u16 {
        u16::from_le_bytes([self.data[off], self.data[off + 1]])
    }

    /// Writes a u32 little-endian to offset.
    fn write_u32(&mut self, off: usize, v: u32) {
        let bytes = v.to_le_bytes();
        self.data[off..off + 4].copy_from_slice(&bytes);
        self.dirty = true;
    }

    /// Writes a u16 little-endian to offset.
    fn write_u16(&mut self, off: usize, v: u16) {
        let bytes = v.to_le_bytes();
        self.data[off..off + 2].copy_from_slice(&bytes);
        self.dirty = true;
    }

    /// Parses a directory entry at the given offset.
    pub fn parse_entry(&self, off: usize) -> Option<(Ext2DirEntry, usize)> {
        if off + 8 > DIR_BLOCK_SIZE {
            return None;
        }
        let inode = self.read_u32(off);
        let rec_len = self.read_u16(off + 4);
        let name_len = self.data[off + 6];
        let file_type = self.data[off + 7];

        if rec_len < 8 || off + rec_len as usize > DIR_BLOCK_SIZE {
            return None;
        }
        if name_len as usize > MAX_NAME_LEN {
            return None;
        }
        let mut name = [0u8; MAX_NAME_LEN];
        let nlen = name_len as usize;
        if off + 8 + nlen > DIR_BLOCK_SIZE {
            return None;
        }
        name[..nlen].copy_from_slice(&self.data[off + 8..off + 8 + nlen]);

        Some((
            Ext2DirEntry {
                inode,
                rec_len,
                name_len,
                file_type,
                name,
            },
            off + rec_len as usize,
        ))
    }

    /// Writes a directory entry at the given offset.
    fn write_entry(&mut self, off: usize, entry: &Ext2DirEntry) {
        self.write_u32(off, entry.inode);
        self.write_u16(off + 4, entry.rec_len);
        self.data[off + 6] = entry.name_len;
        self.data[off + 7] = entry.file_type;
        let nlen = entry.name_len as usize;
        self.data[off + 8..off + 8 + nlen].copy_from_slice(&entry.name[..nlen]);
        self.dirty = true;
    }
}

impl Default for DirBlock {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Directory operations
// ---------------------------------------------------------------------------

/// Reads all directory entries from a block.
///
/// Returns all active entries (inode != 0). The caller provides an output
/// array; up to `MAX_READDIR_ENTRIES` are returned.
pub fn ext2_readdir(
    block: &DirBlock,
    out: &mut [Option<Ext2DirEntry>; MAX_READDIR_ENTRIES],
) -> usize {
    let mut off = 0usize;
    let mut count = 0usize;

    while off < DIR_BLOCK_SIZE && count < MAX_READDIR_ENTRIES {
        match block.parse_entry(off) {
            None => break,
            Some((entry, next_off)) => {
                if entry.is_active() {
                    out[count] = Some(entry);
                    count += 1;
                }
                off = next_off;
            }
        }
    }
    count
}

/// Looks up a directory entry by name.
///
/// Returns a copy of the matching entry.
pub fn ext2_lookup(block: &DirBlock, name: &[u8]) -> Result<Ext2DirEntry> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(Error::InvalidArgument);
    }
    let mut off = 0usize;
    while off < DIR_BLOCK_SIZE {
        match block.parse_entry(off) {
            None => break,
            Some((entry, next_off)) => {
                if entry.is_active() && entry.name_bytes() == name {
                    return Ok(entry);
                }
                off = next_off;
            }
        }
    }
    Err(Error::NotFound)
}

/// Adds a new directory entry to a block.
///
/// Scans for a deleted entry with enough slack space, or appends at end.
pub fn ext2_add_entry(block: &mut DirBlock, new_entry: Ext2DirEntry) -> Result<()> {
    let needed = Ext2DirEntry::needed_rec_len(new_entry.name_len as usize);
    let mut off = 0usize;

    while off < DIR_BLOCK_SIZE {
        match block.parse_entry(off) {
            None => {
                // End of entries. Write here if space.
                if off + needed <= DIR_BLOCK_SIZE {
                    let remaining = DIR_BLOCK_SIZE - off;
                    let mut e = new_entry;
                    e.rec_len = remaining as u16;
                    block.write_entry(off, &e);
                    return Ok(());
                }
                return Err(Error::OutOfMemory);
            }
            Some((entry, next_off)) => {
                let slack = entry.slack();
                if !entry.is_active() && entry.rec_len as usize >= needed {
                    // Reuse deleted entry slot.
                    let mut e = new_entry;
                    e.rec_len = entry.rec_len;
                    block.write_entry(off, &e);
                    return Ok(());
                }
                if slack >= needed {
                    // Split: shrink existing entry, write new after it.
                    let actual = entry.actual_len();
                    let new_off = off + actual;

                    // Update existing entry's rec_len.
                    let new_rec_len = actual as u16;
                    block.write_u16(off + 4, new_rec_len);

                    // Write new entry in the slack space.
                    let remaining = entry.rec_len as usize - actual;
                    let mut e = new_entry;
                    e.rec_len = remaining as u16;
                    block.write_entry(new_off, &e);
                    return Ok(());
                }
                off = next_off;
            }
        }
    }
    Err(Error::OutOfMemory)
}

/// Removes a directory entry by name.
///
/// Merges the deleted entry's space with the previous entry (or marks
/// inode=0 if it's the first entry in the block).
pub fn ext2_remove_entry(block: &mut DirBlock, name: &[u8]) -> Result<u32> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(Error::InvalidArgument);
    }

    let mut prev_off: Option<usize> = None;
    let mut off = 0usize;

    while off < DIR_BLOCK_SIZE {
        match block.parse_entry(off) {
            None => break,
            Some((entry, next_off)) => {
                if entry.is_active() && entry.name_bytes() == name {
                    let removed_ino = entry.inode;
                    if let Some(poff) = prev_off {
                        // Merge with previous: extend prev rec_len.
                        let prev_rec = block.read_u16(poff + 4);
                        block.write_u16(poff + 4, prev_rec + entry.rec_len);
                    } else {
                        // First entry: just zero the inode.
                        block.write_u32(off, 0);
                    }
                    return Ok(removed_ino);
                }
                prev_off = Some(off);
                off = next_off;
            }
        }
    }
    Err(Error::NotFound)
}

/// Initializes an empty directory block with `.` and `..` entries.
pub fn ext2_init_dir_block(block: &mut DirBlock, dir_ino: u32, parent_ino: u32) -> Result<()> {
    let dot = Ext2DirEntry::new(dir_ino, b".", EXT2_FT_DIR)?;
    let dotdot = Ext2DirEntry::new(parent_ino, b"..", EXT2_FT_DIR)?;
    ext2_add_entry(block, dot)?;
    ext2_add_entry(block, dotdot)?;
    Ok(())
}
