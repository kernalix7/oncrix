// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ext4 extended attributes stored in inodes.
//!
//! Implements the inline xattr scheme used by ext4 where xattr data is stored
//! directly in the inode body (after the fixed inode fields) and, when that
//! space is exhausted, in a dedicated external xattr block.
//!
//! # Layout
//!
//! The inline xattr area starts immediately after the standard inode fields
//! (offset 0x80 in a 256-byte inode, or `i_extra_isize` bytes in from field
//! end). Each entry consists of a fixed [`XattrEntryHeader`] followed by the
//! attribute name (not NUL-terminated, `name_len` bytes) and value
//! (`value_len` bytes), packed consecutively with 4-byte alignment.
//!
//! # References
//!
//! - Linux `fs/ext4/xattr.c`, `fs/ext4/xattr.h`
//! - ext4 documentation: <https://www.kernel.org/doc/html/latest/filesystems/ext4/>

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Magic number that precedes the first xattr entry in an inode or block.
pub const EXT4_XATTR_MAGIC: u32 = 0xEA02_0000;

/// Alignment granularity for xattr values within the storage area (bytes).
pub const XATTR_ALIGN: usize = 4;

/// Maximum total inline xattr storage per inode (bytes).
pub const INLINE_XATTR_MAX: usize = 128;

/// Maximum number of inline xattr entries stored per inode.
pub const MAX_INLINE_ENTRIES: usize = 16;

/// Maximum number of entries in an external xattr block.
pub const MAX_BLOCK_ENTRIES: usize = 64;

/// Maximum byte length of a single xattr name.
pub const XATTR_NAME_MAX_LEN: usize = 255;

/// Maximum byte length of a single xattr value.
pub const XATTR_VALUE_MAX_LEN: usize = 65536;

/// Name index for the `user.` namespace.
pub const EXT4_XATTR_INDEX_USER: u8 = 1;

/// Name index for the `system.posix_acl_access` attribute.
pub const EXT4_XATTR_INDEX_POSIX_ACL_ACCESS: u8 = 2;

/// Name index for the `system.posix_acl_default` attribute.
pub const EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT: u8 = 3;

/// Name index for the `trusted.` namespace.
pub const EXT4_XATTR_INDEX_TRUSTED: u8 = 4;

/// Name index for the `security.` namespace.
pub const EXT4_XATTR_INDEX_SECURITY: u8 = 6;

// ── XattrEntryHeader ─────────────────────────────────────────────────────────

/// Fixed-size header that precedes each xattr entry in storage.
///
/// Mirrors the `ext4_xattr_entry` structure in `fs/ext4/xattr.h`.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct XattrEntryHeader {
    /// Length of the attribute name (bytes, not NUL-terminated).
    pub name_len: u8,
    /// Index encoding the attribute namespace.
    pub name_index: u8,
    /// Offset of the value from the start of the storage area.
    pub value_offs: u16,
    /// Inode number of the value (for value in separate inode; 0 = inline).
    pub value_inum: u32,
    /// Length of the attribute value in bytes.
    pub value_len: u32,
    /// Reference hash of name+value (used for fast lookup).
    pub hash: u32,
}

impl XattrEntryHeader {
    /// Returns the total on-disk size of this entry including name and value,
    /// rounded up to [`XATTR_ALIGN`] bytes.
    pub const fn entry_size(&self) -> usize {
        let raw = core::mem::size_of::<XattrEntryHeader>()
            + self.name_len as usize
            + self.value_len as usize;
        (raw + XATTR_ALIGN - 1) & !(XATTR_ALIGN - 1)
    }
}

// ── XattrEntry ───────────────────────────────────────────────────────────────

/// A fully decoded xattr entry (header + name + value).
#[derive(Debug, Clone, Copy)]
pub struct XattrEntry {
    /// Parsed header fields.
    pub header: XattrEntryHeader,
    /// Attribute name bytes (length given by `header.name_len`).
    name_buf: [u8; XATTR_NAME_MAX_LEN],
    /// Attribute value bytes (length given by `header.value_len`).
    value_buf: [u8; 512],
    /// Whether this slot is in use.
    active: bool,
}

impl Default for XattrEntry {
    fn default() -> Self {
        Self {
            header: XattrEntryHeader::default(),
            name_buf: [0u8; XATTR_NAME_MAX_LEN],
            value_buf: [0u8; 512],
            active: false,
        }
    }
}

impl XattrEntry {
    /// Returns the attribute name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name_buf[..self.header.name_len as usize]
    }

    /// Returns the attribute value as a byte slice.
    pub fn value(&self) -> &[u8] {
        &self.value_buf[..self.header.value_len as usize]
    }
}

// ── InodeXattrStore ───────────────────────────────────────────────────────────

/// Inline xattr storage embedded in an ext4 inode body.
///
/// Holds up to [`MAX_INLINE_ENTRIES`] entries packed in a fixed-size byte
/// region. When the region is exhausted, callers should spill to an external
/// xattr block (see [`XattrBlock`]).
#[derive(Debug)]
pub struct InodeXattrStore {
    /// Decoded entries.
    entries: [XattrEntry; MAX_INLINE_ENTRIES],
    /// Number of active entries.
    count: usize,
    /// Raw bytes consumed by current entries (tracks inline budget).
    bytes_used: usize,
    /// Inode number this store belongs to.
    inode_no: u64,
}

impl Default for InodeXattrStore {
    fn default() -> Self {
        Self {
            entries: [const {
                XattrEntry {
                    header: XattrEntryHeader {
                        name_len: 0,
                        name_index: 0,
                        value_offs: 0,
                        value_inum: 0,
                        value_len: 0,
                        hash: 0,
                    },
                    name_buf: [0u8; XATTR_NAME_MAX_LEN],
                    value_buf: [0u8; 512],
                    active: false,
                }
            }; MAX_INLINE_ENTRIES],
            count: 0,
            bytes_used: 0,
            inode_no: 0,
        }
    }
}

impl InodeXattrStore {
    /// Creates a new empty inline xattr store for the given inode.
    pub const fn new(inode_no: u64) -> Self {
        Self {
            entries: [const {
                XattrEntry {
                    header: XattrEntryHeader {
                        name_len: 0,
                        name_index: 0,
                        value_offs: 0,
                        value_inum: 0,
                        value_len: 0,
                        hash: 0,
                    },
                    name_buf: [0u8; XATTR_NAME_MAX_LEN],
                    value_buf: [0u8; 512],
                    active: false,
                }
            }; MAX_INLINE_ENTRIES],
            count: 0,
            bytes_used: 0,
            inode_no,
        }
    }

    /// Returns the inode number this store is attached to.
    pub const fn inode_no(&self) -> u64 {
        self.inode_no
    }

    /// Searches for an entry by `name_index` and `name`.
    pub fn get(&self, name_index: u8, name: &[u8]) -> Option<&XattrEntry> {
        self.entries[..self.count]
            .iter()
            .find(|e| e.active && e.header.name_index == name_index && e.name() == name)
    }

    /// Sets or replaces an xattr entry.
    ///
    /// Returns [`Error::InvalidArgument`] if the name or value exceeds the
    /// maximum length. Returns [`Error::OutOfMemory`] if the inline area is
    /// full.
    pub fn set(&mut self, name_index: u8, name: &[u8], value: &[u8]) -> Result<()> {
        if name.len() > XATTR_NAME_MAX_LEN {
            return Err(Error::InvalidArgument);
        }
        if value.len() > 512 {
            return Err(Error::OutOfMemory); // value too large for inline
        }

        // Try to update an existing entry first.
        for i in 0..self.count {
            if self.entries[i].active
                && self.entries[i].header.name_index == name_index
                && self.entries[i].name() == name
            {
                let old_size = self.entries[i].header.entry_size();
                let new_header = build_header(name_index, name, value);
                let new_size = new_header.entry_size();
                let delta = new_size.saturating_sub(old_size);
                if self.bytes_used + delta > INLINE_XATTR_MAX {
                    return Err(Error::OutOfMemory);
                }
                self.bytes_used = self.bytes_used - old_size + new_size;
                self.entries[i].header = new_header;
                self.entries[i].value_buf[..value.len()].copy_from_slice(value);
                return Ok(());
            }
        }

        // New entry.
        if self.count >= MAX_INLINE_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let hdr = build_header(name_index, name, value);
        if self.bytes_used + hdr.entry_size() > INLINE_XATTR_MAX {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.entries[idx].header = hdr;
        self.entries[idx].name_buf[..name.len()].copy_from_slice(name);
        self.entries[idx].value_buf[..value.len()].copy_from_slice(value);
        self.entries[idx].active = true;
        self.bytes_used += hdr.entry_size();
        self.count += 1;
        Ok(())
    }

    /// Removes an xattr entry.
    ///
    /// Returns [`Error::NotFound`] if no matching entry exists.
    pub fn remove(&mut self, name_index: u8, name: &[u8]) -> Result<()> {
        let pos = self.entries[..self.count]
            .iter()
            .position(|e| e.active && e.header.name_index == name_index && e.name() == name)
            .ok_or(Error::NotFound)?;
        let freed = self.entries[pos].header.entry_size();
        self.entries[pos] = self.entries[self.count - 1];
        self.entries[self.count - 1] = XattrEntry::default();
        self.count -= 1;
        self.bytes_used = self.bytes_used.saturating_sub(freed);
        Ok(())
    }

    /// Iterates over active entries, calling `f` for each one.
    pub fn iter_entries<F: FnMut(&XattrEntry)>(&self, mut f: F) {
        for e in &self.entries[..self.count] {
            if e.active {
                f(e);
            }
        }
    }

    /// Returns the number of bytes consumed in the inline area.
    pub const fn bytes_used(&self) -> usize {
        self.bytes_used
    }

    /// Returns `true` if the inline area has insufficient space to hold an
    /// additional entry with the given name and value sizes.
    pub fn would_overflow(&self, name_len: usize, value_len: usize) -> bool {
        let needed = core::mem::size_of::<XattrEntryHeader>() + name_len + value_len;
        let aligned = (needed + XATTR_ALIGN - 1) & !(XATTR_ALIGN - 1);
        self.bytes_used + aligned > INLINE_XATTR_MAX
    }
}

// ── XattrBlock ───────────────────────────────────────────────────────────────

/// An external xattr block used for overflow when the inline area is full.
///
/// A block holds up to [`MAX_BLOCK_ENTRIES`] entries and is addressed by the
/// inode's `i_file_acl` field.
#[derive(Debug)]
pub struct XattrBlock {
    /// Magic word (should equal [`EXT4_XATTR_MAGIC`] after deserialization).
    magic: u32,
    /// Entries stored in this block.
    entries: [XattrEntry; MAX_BLOCK_ENTRIES],
    /// Number of active entries.
    count: usize,
    /// Block number on disk (0 = not yet allocated).
    block_no: u64,
}

impl Default for XattrBlock {
    fn default() -> Self {
        Self {
            magic: EXT4_XATTR_MAGIC,
            entries: [const {
                XattrEntry {
                    header: XattrEntryHeader {
                        name_len: 0,
                        name_index: 0,
                        value_offs: 0,
                        value_inum: 0,
                        value_len: 0,
                        hash: 0,
                    },
                    name_buf: [0u8; XATTR_NAME_MAX_LEN],
                    value_buf: [0u8; 512],
                    active: false,
                }
            }; MAX_BLOCK_ENTRIES],
            count: 0,
            block_no: 0,
        }
    }
}

impl XattrBlock {
    /// Creates a new, empty xattr block.
    pub const fn new(block_no: u64) -> Self {
        Self {
            magic: EXT4_XATTR_MAGIC,
            entries: [const {
                XattrEntry {
                    header: XattrEntryHeader {
                        name_len: 0,
                        name_index: 0,
                        value_offs: 0,
                        value_inum: 0,
                        value_len: 0,
                        hash: 0,
                    },
                    name_buf: [0u8; XATTR_NAME_MAX_LEN],
                    value_buf: [0u8; 512],
                    active: false,
                }
            }; MAX_BLOCK_ENTRIES],
            count: 0,
            block_no,
        }
    }

    /// Returns the block number.
    pub const fn block_no(&self) -> u64 {
        self.block_no
    }

    /// Validates the block magic word.
    pub const fn is_valid(&self) -> bool {
        self.magic == EXT4_XATTR_MAGIC
    }

    /// Looks up an entry by namespace index and name.
    pub fn get(&self, name_index: u8, name: &[u8]) -> Option<&XattrEntry> {
        self.entries[..self.count]
            .iter()
            .find(|e| e.active && e.header.name_index == name_index && e.name() == name)
    }

    /// Inserts or replaces an xattr entry in the block.
    ///
    /// Returns [`Error::OutOfMemory`] if the block is full.
    pub fn set(&mut self, name_index: u8, name: &[u8], value: &[u8]) -> Result<()> {
        if name.len() > XATTR_NAME_MAX_LEN || value.len() > 512 {
            return Err(Error::InvalidArgument);
        }
        // Update existing.
        for i in 0..self.count {
            if self.entries[i].active
                && self.entries[i].header.name_index == name_index
                && self.entries[i].name() == name
            {
                self.entries[i].header = build_header(name_index, name, value);
                self.entries[i].value_buf[..value.len()].copy_from_slice(value);
                return Ok(());
            }
        }
        if self.count >= MAX_BLOCK_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.entries[idx].header = build_header(name_index, name, value);
        self.entries[idx].name_buf[..name.len()].copy_from_slice(name);
        self.entries[idx].value_buf[..value.len()].copy_from_slice(value);
        self.entries[idx].active = true;
        self.count += 1;
        Ok(())
    }

    /// Removes an entry from the block.
    ///
    /// Returns [`Error::NotFound`] if no matching entry exists.
    pub fn remove(&mut self, name_index: u8, name: &[u8]) -> Result<()> {
        let pos = self.entries[..self.count]
            .iter()
            .position(|e| e.active && e.header.name_index == name_index && e.name() == name)
            .ok_or(Error::NotFound)?;
        self.entries[pos] = self.entries[self.count - 1];
        self.entries[self.count - 1] = XattrEntry::default();
        self.count -= 1;
        Ok(())
    }

    /// Iterates over all active entries in the block.
    pub fn iter_entries<F: FnMut(&XattrEntry)>(&self, mut f: F) {
        for e in &self.entries[..self.count] {
            if e.active {
                f(e);
            }
        }
    }

    /// Returns the number of entries currently stored.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the block contains no entries.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ── XattrInodeStore (combined) ────────────────────────────────────────────────

/// Combined inline + overflow xattr store for a single ext4 inode.
///
/// Transparently handles spill-over from the inline area to the external block
/// when the inline budget is exhausted.
pub struct XattrInodeStore {
    /// Inline xattr storage (always present).
    pub inline: InodeXattrStore,
    /// External xattr block (allocated on demand).
    pub block: Option<XattrBlock>,
}

impl XattrInodeStore {
    /// Creates a new store for `inode_no` with no inline entries and no block.
    pub const fn new(inode_no: u64) -> Self {
        Self {
            inline: InodeXattrStore::new(inode_no),
            block: None,
        }
    }

    /// Gets an xattr value from either the inline area or external block.
    pub fn get(&self, name_index: u8, name: &[u8]) -> Option<&XattrEntry> {
        self.inline
            .get(name_index, name)
            .or_else(|| self.block.as_ref().and_then(|b| b.get(name_index, name)))
    }

    /// Sets an xattr. Attempts inline first; spills to block on overflow.
    ///
    /// Returns [`Error::OutOfMemory`] if both inline and block are full.
    pub fn set(&mut self, name_index: u8, name: &[u8], value: &[u8], block_no: u64) -> Result<()> {
        match self.inline.set(name_index, name, value) {
            Ok(()) => Ok(()),
            Err(Error::OutOfMemory) => {
                // Spill to external block.
                if self.block.is_none() {
                    self.block = Some(XattrBlock::new(block_no));
                }
                self.block.as_mut().unwrap().set(name_index, name, value)
            }
            Err(e) => Err(e),
        }
    }

    /// Removes an xattr from whichever area holds it.
    pub fn remove(&mut self, name_index: u8, name: &[u8]) -> Result<()> {
        if self.inline.remove(name_index, name).is_ok() {
            return Ok(());
        }
        self.block
            .as_mut()
            .ok_or(Error::NotFound)?
            .remove(name_index, name)
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Constructs an [`XattrEntryHeader`] from component parts.
fn build_header(name_index: u8, name: &[u8], value: &[u8]) -> XattrEntryHeader {
    XattrEntryHeader {
        name_len: name.len() as u8,
        name_index,
        value_offs: 0,
        value_inum: 0,
        value_len: value.len() as u32,
        hash: simple_hash(name, value),
    }
}

/// Computes a simple djb2-style hash over name and value bytes.
fn simple_hash(name: &[u8], value: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in name.iter().chain(value.iter()) {
        h = h.wrapping_mul(33).wrapping_add(b as u32);
    }
    h
}
