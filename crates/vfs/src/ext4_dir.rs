// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ext4 directory operations.
//!
//! Implements ext4 directory entry structures and operations:
//! - [`Ext4DirEntry`] — on-disk directory entry (rec_len, name_len, file_type)
//! - Linear directory scan and htree (hash-tree) lookup stubs
//! - [`ext4_readdir`] — iterate all entries in a directory block
//! - [`ext4_add_entry`] — append a new entry to a directory
//! - [`ext4_remove_entry`] — logically delete an entry by merging rec_len
//! - Proper dot/dotdot handling on directory creation
//!
//! # References
//! - Linux `fs/ext4/dir.c`, `fs/ext4/namei.c`
//! - ext4 disk layout wiki

extern crate alloc;
use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum file name length in ext4.
pub const EXT4_NAME_LEN: usize = 255;

/// Maximum directory block size (4 KiB).
const EXT4_DIR_BLOCK_SIZE: usize = 4096;

/// Minimum directory entry size (without name).
const EXT4_DIR_ENTRY_MIN_SIZE: usize = 8;

/// Maximum directory entries per block.
const MAX_ENTRIES_PER_BLOCK: usize = 256;

/// Maximum entries in the readdir result buffer.
const MAX_READDIR_ENTRIES: usize = 512;

// ---------------------------------------------------------------------------
// File type constants (stored in dir entry)
// ---------------------------------------------------------------------------

/// Unknown file type.
pub const EXT4_FT_UNKNOWN: u8 = 0;
/// Regular file.
pub const EXT4_FT_REG_FILE: u8 = 1;
/// Directory.
pub const EXT4_FT_DIR: u8 = 2;
/// Character device.
pub const EXT4_FT_CHRDEV: u8 = 3;
/// Block device.
pub const EXT4_FT_BLKDEV: u8 = 4;
/// FIFO (named pipe).
pub const EXT4_FT_FIFO: u8 = 5;
/// Socket.
pub const EXT4_FT_SOCK: u8 = 6;
/// Symbolic link.
pub const EXT4_FT_SYMLINK: u8 = 7;

// ---------------------------------------------------------------------------
// Ext4DirEntry
// ---------------------------------------------------------------------------

/// ext4 on-disk directory entry (`ext4_dir_entry_2`).
///
/// Entries are variable-length: actual record occupies `rec_len` bytes.
/// The `name` field stores the entry name (not NUL-terminated on disk).
#[derive(Debug, Clone)]
pub struct Ext4DirEntry {
    /// Inode number (0 means deleted/empty entry).
    pub inode: u32,
    /// Length of this directory record (includes header + name + padding).
    pub rec_len: u16,
    /// Length of the file name.
    pub name_len: u8,
    /// File type (EXT4_FT_* constant).
    pub file_type: u8,
    /// File name (up to EXT4_NAME_LEN bytes).
    pub name: [u8; EXT4_NAME_LEN],
}

impl Ext4DirEntry {
    /// Create a new directory entry.
    ///
    /// Returns `Err(InvalidArgument)` if `name` exceeds `EXT4_NAME_LEN`.
    pub fn new(inode: u32, file_type: u8, name: &[u8]) -> Result<Self> {
        if name.len() > EXT4_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut entry = Self {
            inode,
            rec_len: 0,
            name_len: name.len() as u8,
            file_type,
            name: [0u8; EXT4_NAME_LEN],
        };
        entry.name[..name.len()].copy_from_slice(name);
        // rec_len = header(8) + name_len, rounded up to 4-byte boundary.
        let raw = EXT4_DIR_ENTRY_MIN_SIZE + name.len();
        entry.rec_len = ((raw + 3) & !3) as u16;
        Ok(entry)
    }

    /// Return the name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Return true if this entry is a dot entry ("." or "..").
    pub fn is_dot(&self) -> bool {
        let n = self.name_bytes();
        n == b"." || n == b".."
    }

    /// Return true if the entry slot is free (inode == 0).
    pub fn is_free(&self) -> bool {
        self.inode == 0
    }

    /// Compute the minimal record length for a name of given length.
    pub fn min_rec_len(name_len: usize) -> u16 {
        let raw = EXT4_DIR_ENTRY_MIN_SIZE + name_len;
        ((raw + 3) & !3) as u16
    }
}

// ---------------------------------------------------------------------------
// Ext4DirBlock — a 4 KiB block holding directory entries
// ---------------------------------------------------------------------------

/// A 4 KiB directory block containing packed `Ext4DirEntry` records.
pub struct Ext4DirBlock {
    entries: [Option<Ext4DirEntry>; MAX_ENTRIES_PER_BLOCK],
    count: usize,
}

impl Ext4DirBlock {
    /// Create an empty directory block.
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            count: 0,
        }
    }

    /// Initialize as a fresh directory (with "." and "..").
    ///
    /// `self_ino` — inode number of this directory.
    /// `parent_ino` — inode number of the parent directory.
    pub fn init_dir(&mut self, self_ino: u32, parent_ino: u32) -> Result<()> {
        let dot = Ext4DirEntry::new(self_ino, EXT4_FT_DIR, b".")?;
        let dotdot = Ext4DirEntry::new(parent_ino, EXT4_FT_DIR, b"..")?;
        self.entries[0] = Some(dot);
        self.entries[1] = Some(dotdot);
        self.count = 2;
        Ok(())
    }

    /// Look up an entry by name (linear scan).
    ///
    /// Returns `Some(&Ext4DirEntry)` if found, `None` otherwise.
    pub fn linear_lookup(&self, name: &[u8]) -> Option<&Ext4DirEntry> {
        for slot in &self.entries[..self.count] {
            if let Some(e) = slot {
                if !e.is_free() && e.name_bytes() == name {
                    return Some(e);
                }
            }
        }
        None
    }

    /// HTree (hash-tree) lookup stub.
    ///
    /// For large directories ext4 uses a radix hash-tree. This stub falls
    /// back to linear scan and is a placeholder for a full htree walker.
    pub fn htree_lookup(&self, name: &[u8]) -> Option<&Ext4DirEntry> {
        // Full htree requires parsing DX_ROOT / DX_NODE blocks from disk.
        // For now, delegate to the linear path.
        self.linear_lookup(name)
    }

    /// Find an entry slot large enough to hold `needed_rec_len`.
    fn find_free_slot(&self, needed: u16) -> Option<usize> {
        // First try a fully free slot.
        for (i, slot) in self.entries[..self.count].iter().enumerate() {
            if let Some(e) = slot {
                if e.is_free() && e.rec_len >= needed {
                    return Some(i);
                }
            }
        }
        // Then try to extend the count.
        if self.count < MAX_ENTRIES_PER_BLOCK {
            return Some(self.count);
        }
        None
    }
}

// ---------------------------------------------------------------------------
// ext4_readdir
// ---------------------------------------------------------------------------

/// Iterate all valid directory entries in the block.
///
/// Skips deleted (inode == 0) entries. Returns up to `MAX_READDIR_ENTRIES`
/// results.
pub fn ext4_readdir(block: &Ext4DirBlock) -> Vec<Ext4DirEntry> {
    let mut result = Vec::new();
    for slot in &block.entries[..block.count] {
        if result.len() >= MAX_READDIR_ENTRIES {
            break;
        }
        if let Some(e) = slot {
            if !e.is_free() {
                result.push(e.clone());
            }
        }
    }
    result
}

// ---------------------------------------------------------------------------
// ext4_add_entry
// ---------------------------------------------------------------------------

/// Append a new directory entry to `block`.
///
/// Finds a free or split-able slot, fills in the new entry and returns its
/// index within the block. Returns `Err(OutOfMemory)` when the block is full.
pub fn ext4_add_entry(
    block: &mut Ext4DirBlock,
    inode: u32,
    file_type: u8,
    name: &[u8],
) -> Result<usize> {
    if name.len() > EXT4_NAME_LEN {
        return Err(Error::InvalidArgument);
    }
    let new_entry = Ext4DirEntry::new(inode, file_type, name)?;
    let needed = new_entry.rec_len;

    // Try to find an existing free slot wide enough.
    if let Some(idx) = block.find_free_slot(needed) {
        if idx == block.count {
            if block.count >= MAX_ENTRIES_PER_BLOCK {
                return Err(Error::OutOfMemory);
            }
            block.count += 1;
        }
        block.entries[idx] = Some(new_entry);
        return Ok(idx);
    }

    // Try to split a large existing entry if it has unused trailing space.
    for i in 0..block.count {
        if let Some(existing) = block.entries[i].as_mut() {
            let used = Ext4DirEntry::min_rec_len(existing.name_len as usize);
            let spare = existing.rec_len.saturating_sub(used);
            if spare >= needed {
                let leftover_rec_len = existing.rec_len - needed;
                existing.rec_len = used + leftover_rec_len;
                // Insert new entry after by shifting is complex in fixed
                // arrays; instead append at count position with adjusted
                // rec_len.
                if block.count < MAX_ENTRIES_PER_BLOCK {
                    let mut entry = new_entry.clone();
                    entry.rec_len = needed;
                    let idx = block.count;
                    block.entries[idx] = Some(entry);
                    block.count += 1;
                    return Ok(idx);
                }
            }
        }
    }

    Err(Error::OutOfMemory)
}

// ---------------------------------------------------------------------------
// ext4_remove_entry
// ---------------------------------------------------------------------------

/// Remove a directory entry by name.
///
/// Marks the entry as free (inode = 0) and merges its `rec_len` into the
/// previous entry's `rec_len` if possible (as ext4 does on disk).
/// Returns `Err(NotFound)` if no matching entry exists.
pub fn ext4_remove_entry(block: &mut Ext4DirBlock, name: &[u8]) -> Result<()> {
    let mut target_idx = None;
    for (i, slot) in block.entries[..block.count].iter().enumerate() {
        if let Some(e) = slot {
            if !e.is_free() && e.name_bytes() == name {
                target_idx = Some(i);
                break;
            }
        }
    }
    let idx = target_idx.ok_or(Error::NotFound)?;

    // Mark as free.
    if let Some(e) = block.entries[idx].as_mut() {
        e.inode = 0;
        e.name_len = 0;
    }

    // Attempt to merge with previous entry to recover contiguous space.
    if idx > 0 {
        if let (Some(prev), Some(cur)) =
            (block.entries[idx - 1].as_ref(), block.entries[idx].as_ref())
        {
            let merged = prev.rec_len.saturating_add(cur.rec_len);
            let merged_len = merged;
            let prev_inode = prev.inode;
            if prev_inode != 0 {
                // Only merge free tail into live previous entry.
                if let Some(prev_entry) = block.entries[idx - 1].as_mut() {
                    prev_entry.rec_len = merged_len;
                }
                block.entries[idx] = None;
                // Compact the count if idx is the last slot.
                if idx == block.count - 1 {
                    block.count -= 1;
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Ext4Dir — directory abstraction managing multiple blocks
// ---------------------------------------------------------------------------

/// Maximum number of data blocks in a directory (simple flat layout).
const MAX_DIR_BLOCKS: usize = 8;

/// An ext4 directory abstraction managing up to `MAX_DIR_BLOCKS` blocks.
pub struct Ext4Dir {
    /// Inode number of this directory.
    pub ino: u32,
    /// Inode number of the parent directory.
    pub parent_ino: u32,
    blocks: [Option<Ext4DirBlock>; MAX_DIR_BLOCKS],
    block_count: usize,
}

impl Ext4Dir {
    /// Create and initialise a new empty directory.
    pub fn new(ino: u32, parent_ino: u32) -> Result<Self> {
        let mut dir = Self {
            ino,
            parent_ino,
            blocks: core::array::from_fn(|_| None),
            block_count: 0,
        };
        let mut first_block = Ext4DirBlock::new();
        first_block.init_dir(ino, parent_ino)?;
        dir.blocks[0] = Some(first_block);
        dir.block_count = 1;
        Ok(dir)
    }

    /// Look up an entry across all blocks.
    pub fn lookup(&self, name: &[u8]) -> Result<Ext4DirEntry> {
        for block in self.blocks[..self.block_count].iter().flatten() {
            if let Some(e) = block.linear_lookup(name) {
                return Ok(e.clone());
            }
        }
        Err(Error::NotFound)
    }

    /// Add an entry, extending to a new block if the current one is full.
    pub fn add_entry(&mut self, inode: u32, file_type: u8, name: &[u8]) -> Result<()> {
        // Try existing blocks first.
        for block in self.blocks[..self.block_count].iter_mut().flatten() {
            if ext4_add_entry(block, inode, file_type, name).is_ok() {
                return Ok(());
            }
        }
        // Allocate a new block.
        if self.block_count >= MAX_DIR_BLOCKS {
            return Err(Error::OutOfMemory);
        }
        let mut new_block = Ext4DirBlock::new();
        ext4_add_entry(&mut new_block, inode, file_type, name)?;
        self.blocks[self.block_count] = Some(new_block);
        self.block_count += 1;
        Ok(())
    }

    /// Remove an entry from any block.
    pub fn remove_entry(&mut self, name: &[u8]) -> Result<()> {
        for block in self.blocks[..self.block_count].iter_mut().flatten() {
            if ext4_remove_entry(block, name).is_ok() {
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Read all entries from all blocks.
    pub fn readdir(&self) -> Vec<Ext4DirEntry> {
        let mut all = Vec::new();
        for block in self.blocks[..self.block_count].iter().flatten() {
            all.extend(ext4_readdir(block));
        }
        all
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_dir_and_lookup() {
        let mut dir = Ext4Dir::new(10, 2).unwrap();
        dir.add_entry(20, EXT4_FT_REG_FILE, b"hello.txt").unwrap();
        let e = dir.lookup(b"hello.txt").unwrap();
        assert_eq!(e.inode, 20);
    }

    #[test]
    fn test_remove_entry() {
        let mut dir = Ext4Dir::new(10, 2).unwrap();
        dir.add_entry(20, EXT4_FT_REG_FILE, b"file.txt").unwrap();
        dir.remove_entry(b"file.txt").unwrap();
        assert!(dir.lookup(b"file.txt").is_err());
    }

    #[test]
    fn test_dot_dotdot_present() {
        let dir = Ext4Dir::new(10, 2).unwrap();
        dir.lookup(b".").unwrap();
        dir.lookup(b"..").unwrap();
    }
}
