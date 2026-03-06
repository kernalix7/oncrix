// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SquashFS extended attribute support.
//!
//! SquashFS stores extended attributes in a dedicated on-disk table consisting
//! of compressed xattr blocks.  Each inode may reference an xattr index that
//! points into this table.  This module implements the structures for reading,
//! decompressing, and looking up xattrs from a SquashFS image.
//!
//! # On-disk layout
//!
//! ```text
//! SquashFS image:
//! ┌──────────────┬───────────────┬──────────────────────┬──────────┐
//! │ Superblock   │ Data blocks   │ Inode / dir tables   │ Xattr    │
//! │ (96 bytes)   │               │                      │ table    │
//! └──────────────┴───────────────┴──────────────────────┴──────────┘
//!
//! Xattr table:
//! ┌──────────────────────────────────────────────────────────────────┐
//! │ XattrIdTable (header)                                           │
//! │   xattr_ids: u32    — total number of xattr entries             │
//! │   table_start: u64  — byte offset of first xattr block          │
//! ├──────────────────────────────────────────────────────────────────┤
//! │ XattrIndex[0]  — (offset, count, size) for inode 0's xattrs     │
//! │ XattrIndex[1]  — ...                                            │
//! │ ...                                                              │
//! ├──────────────────────────────────────────────────────────────────┤
//! │ XattrBlock[0]  — compressed block of XattrEntry records          │
//! │ XattrBlock[1]  — ...                                            │
//! │ ...                                                              │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Xattr namespaces
//!
//! SquashFS encodes the namespace as a `type` field in each entry:
//! - `0` = `user.`
//! - `1` = `trusted.`
//! - `2` = `security.`
//! - `3` = `system.posix_acl_access`
//! - `4` = `system.posix_acl_default`
//!
//! # Reference
//!
//! Linux `fs/squashfs/xattr.c`, `fs/squashfs/xattr_id.c`,
//! SquashFS on-disk format specification.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum xattr name length (excluding namespace prefix).
const MAX_XATTR_NAME: usize = 255;

/// Maximum xattr value length.
const MAX_XATTR_VALUE: usize = 4096;

/// Maximum number of xattr entries per inode.
const MAX_XATTRS_PER_INODE: usize = 32;

/// Maximum number of xattr index entries in the table.
const MAX_XATTR_INDICES: usize = 256;

/// Maximum number of xattr blocks.
const MAX_XATTR_BLOCKS: usize = 64;

/// Maximum decompressed block size.
const MAX_BLOCK_SIZE: usize = 8192;

/// Namespace prefix for user xattrs.
const NS_USER: &[u8] = b"user.";
/// Namespace prefix for trusted xattrs.
const NS_TRUSTED: &[u8] = b"trusted.";
/// Namespace prefix for security xattrs.
const NS_SECURITY: &[u8] = b"security.";
/// Namespace prefix for system POSIX ACL access.
const NS_POSIX_ACL_ACCESS: &[u8] = b"system.posix_acl_access";
/// Namespace prefix for system POSIX ACL default.
const NS_POSIX_ACL_DEFAULT: &[u8] = b"system.posix_acl_default";

// ── XattrType ─────────────────────────────────────────────────────────────────

/// SquashFS xattr namespace type encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum XattrType {
    /// `user.` namespace.
    User = 0,
    /// `trusted.` namespace.
    Trusted = 1,
    /// `security.` namespace.
    Security = 2,
    /// `system.posix_acl_access`.
    PosixAclAccess = 3,
    /// `system.posix_acl_default`.
    PosixAclDefault = 4,
}

impl XattrType {
    /// Parse a type from its on-disk u16 value.
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0 => Some(Self::User),
            1 => Some(Self::Trusted),
            2 => Some(Self::Security),
            3 => Some(Self::PosixAclAccess),
            4 => Some(Self::PosixAclDefault),
            _ => None,
        }
    }

    /// Return the namespace prefix bytes for this type.
    pub fn prefix(self) -> &'static [u8] {
        match self {
            Self::User => NS_USER,
            Self::Trusted => NS_TRUSTED,
            Self::Security => NS_SECURITY,
            Self::PosixAclAccess => NS_POSIX_ACL_ACCESS,
            Self::PosixAclDefault => NS_POSIX_ACL_DEFAULT,
        }
    }

    /// Return the on-disk numeric id.
    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

// ── XattrEntry ────────────────────────────────────────────────────────────────

/// A single extended attribute entry from a SquashFS xattr block.
///
/// The full attribute name is `<namespace_prefix><name>` (e.g.,
/// `user.mime_type`).  The value is an opaque byte string.
#[derive(Clone)]
pub struct XattrEntry {
    /// Xattr namespace type.
    pub xattr_type: XattrType,
    /// Attribute name (without namespace prefix).
    name: [u8; MAX_XATTR_NAME],
    /// Name length.
    name_len: usize,
    /// Attribute value.
    value: [u8; MAX_XATTR_VALUE],
    /// Value length.
    value_len: usize,
    /// Whether this entry uses an out-of-line value reference.
    pub out_of_line: bool,
}

impl XattrEntry {
    /// Create an empty xattr entry.
    const fn empty() -> Self {
        Self {
            xattr_type: XattrType::User,
            name: [0u8; MAX_XATTR_NAME],
            name_len: 0,
            value: [0u8; MAX_XATTR_VALUE],
            value_len: 0,
            out_of_line: false,
        }
    }

    /// Create a new xattr entry from components.
    pub fn new(
        xattr_type: XattrType,
        name: &[u8],
        value: &[u8],
        out_of_line: bool,
    ) -> Result<Self> {
        if name.len() > MAX_XATTR_NAME || value.len() > MAX_XATTR_VALUE {
            return Err(Error::InvalidArgument);
        }
        let mut na = [0u8; MAX_XATTR_NAME];
        na[..name.len()].copy_from_slice(name);
        let mut va = [0u8; MAX_XATTR_VALUE];
        va[..value.len()].copy_from_slice(value);
        Ok(Self {
            xattr_type,
            name: na,
            name_len: name.len(),
            value: va,
            value_len: value.len(),
            out_of_line,
        })
    }

    /// Return the attribute name (without namespace prefix).
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the attribute value.
    pub fn value_bytes(&self) -> &[u8] {
        &self.value[..self.value_len]
    }

    /// Return the full attribute name with namespace prefix.
    ///
    /// Writes into `buf` and returns the number of bytes written.
    pub fn full_name(&self, buf: &mut [u8]) -> Result<usize> {
        let prefix = self.xattr_type.prefix();
        let total = prefix.len() + self.name_len;
        if total > buf.len() {
            return Err(Error::InvalidArgument);
        }
        buf[..prefix.len()].copy_from_slice(prefix);
        buf[prefix.len()..total].copy_from_slice(&self.name[..self.name_len]);
        Ok(total)
    }

    /// Check whether the full name matches the given byte string.
    pub fn matches_full_name(&self, full_name: &[u8]) -> bool {
        let prefix = self.xattr_type.prefix();
        if full_name.len() != prefix.len() + self.name_len {
            return false;
        }
        if &full_name[..prefix.len()] != prefix {
            return false;
        }
        &full_name[prefix.len()..] == &self.name[..self.name_len]
    }

    /// Return the value length.
    pub fn value_len(&self) -> usize {
        self.value_len
    }
}

impl core::fmt::Debug for XattrEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XattrEntry")
            .field("type", &self.xattr_type)
            .field("name_len", &self.name_len)
            .field("value_len", &self.value_len)
            .field("out_of_line", &self.out_of_line)
            .finish()
    }
}

// ── XattrIndex ────────────────────────────────────────────────────────────────

/// Index entry pointing from an inode to its xattr data in the xattr table.
///
/// Each inode with xattrs has one `XattrIndex` that describes where in the
/// xattr block table its attributes are stored.
#[derive(Debug, Clone, Copy)]
pub struct XattrIndex {
    /// Byte offset into the xattr block table.
    pub offset: u64,
    /// Number of xattr entries for this inode.
    pub count: u16,
    /// Total size of the xattr data (compressed) in bytes.
    pub size: u32,
    /// Inode number this index belongs to.
    pub inode: u64,
    /// Whether this index slot is active.
    pub active: bool,
}

impl XattrIndex {
    /// Create an inactive index entry.
    pub const fn empty() -> Self {
        Self {
            offset: 0,
            count: 0,
            size: 0,
            inode: 0,
            active: false,
        }
    }

    /// Create a new index entry.
    pub const fn new(inode: u64, offset: u64, count: u16, size: u32) -> Self {
        Self {
            offset,
            count,
            size,
            inode,
            active: true,
        }
    }
}

// ── XattrBlock ────────────────────────────────────────────────────────────────

/// A decompressed xattr data block from the SquashFS xattr table.
///
/// Each block contains a sequence of xattr entries that may span multiple
/// inodes.  The block is decompressed on demand and cached.
pub struct XattrBlock {
    /// Decompressed block data.
    data: [u8; MAX_BLOCK_SIZE],
    /// Number of valid bytes in `data`.
    data_len: usize,
    /// Byte offset of this block in the image.
    pub disk_offset: u64,
    /// Compressed size on disk.
    pub compressed_size: u32,
    /// Whether the block was compressed (vs stored raw).
    pub is_compressed: bool,
    /// Whether this slot is loaded.
    pub loaded: bool,
}

impl XattrBlock {
    /// Create an unloaded block slot.
    const fn empty() -> Self {
        Self {
            data: [0u8; MAX_BLOCK_SIZE],
            data_len: 0,
            disk_offset: 0,
            compressed_size: 0,
            is_compressed: false,
            loaded: false,
        }
    }

    /// Load raw (uncompressed) data into this block.
    pub fn load_raw(&mut self, src: &[u8], disk_offset: u64) -> Result<()> {
        if src.len() > MAX_BLOCK_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.data[..src.len()].copy_from_slice(src);
        self.data_len = src.len();
        self.disk_offset = disk_offset;
        self.is_compressed = false;
        self.loaded = true;
        Ok(())
    }

    /// Load decompressed data into this block.
    pub fn load_decompressed(
        &mut self,
        decompressed: &[u8],
        disk_offset: u64,
        compressed_size: u32,
    ) -> Result<()> {
        if decompressed.len() > MAX_BLOCK_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.data[..decompressed.len()].copy_from_slice(decompressed);
        self.data_len = decompressed.len();
        self.disk_offset = disk_offset;
        self.compressed_size = compressed_size;
        self.is_compressed = true;
        self.loaded = true;
        Ok(())
    }

    /// Return the decompressed data.
    pub fn data(&self) -> &[u8] {
        &self.data[..self.data_len]
    }

    /// Read a u16 at the given offset within the block.
    pub fn read_u16(&self, offset: usize) -> Result<u16> {
        if offset + 2 > self.data_len {
            return Err(Error::IoError);
        }
        Ok(u16::from_le_bytes([
            self.data[offset],
            self.data[offset + 1],
        ]))
    }

    /// Read a u32 at the given offset within the block.
    pub fn read_u32(&self, offset: usize) -> Result<u32> {
        if offset + 4 > self.data_len {
            return Err(Error::IoError);
        }
        Ok(u32::from_le_bytes([
            self.data[offset],
            self.data[offset + 1],
            self.data[offset + 2],
            self.data[offset + 3],
        ]))
    }

    /// Read a byte slice at the given offset.
    pub fn read_bytes(&self, offset: usize, len: usize) -> Result<&[u8]> {
        if offset + len > self.data_len {
            return Err(Error::IoError);
        }
        Ok(&self.data[offset..offset + len])
    }
}

impl core::fmt::Debug for XattrBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XattrBlock")
            .field("disk_offset", &self.disk_offset)
            .field("data_len", &self.data_len)
            .field("compressed_size", &self.compressed_size)
            .field("loaded", &self.loaded)
            .finish()
    }
}

// ── SquashfsXattr (main manager) ──────────────────────────────────────────────

/// SquashFS extended attribute manager.
///
/// Manages the xattr index table and block cache for a mounted SquashFS
/// filesystem.  Provides lookup-by-inode and lookup-by-name operations.
pub struct SquashfsXattr {
    /// Xattr index table (one per inode with xattrs).
    indices: [XattrIndex; MAX_XATTR_INDICES],
    /// Number of active index entries.
    index_count: usize,
    /// Xattr block cache.
    blocks: [XattrBlock; MAX_XATTR_BLOCKS],
    /// Number of loaded blocks.
    block_count: usize,
    /// Starting byte offset of the xattr table in the image.
    pub table_start: u64,
    /// Total number of xattr ids (from superblock).
    pub total_xattr_ids: u32,
}

impl SquashfsXattr {
    /// Create an empty xattr manager.
    pub fn new(table_start: u64, total_xattr_ids: u32) -> Self {
        Self {
            indices: [const { XattrIndex::empty() }; MAX_XATTR_INDICES],
            index_count: 0,
            blocks: [const { XattrBlock::empty() }; MAX_XATTR_BLOCKS],
            block_count: 0,
            table_start,
            total_xattr_ids,
        }
    }

    /// Register an xattr index entry for an inode.
    pub fn add_index(&mut self, index: XattrIndex) -> Result<usize> {
        if self.index_count >= MAX_XATTR_INDICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.index_count;
        self.indices[idx] = index;
        self.index_count += 1;
        Ok(idx)
    }

    /// Look up the xattr index entry for a given inode.
    pub fn find_index(&self, inode: u64) -> Option<&XattrIndex> {
        self.indices[..self.index_count]
            .iter()
            .find(|ix| ix.active && ix.inode == inode)
    }

    /// Load a raw xattr block into the cache.
    pub fn load_block_raw(&mut self, data: &[u8], disk_offset: u64) -> Result<usize> {
        if self.block_count >= MAX_XATTR_BLOCKS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.block_count;
        self.blocks[idx].load_raw(data, disk_offset)?;
        self.block_count += 1;
        Ok(idx)
    }

    /// Load a decompressed xattr block into the cache.
    pub fn load_block_decompressed(
        &mut self,
        decompressed: &[u8],
        disk_offset: u64,
        compressed_size: u32,
    ) -> Result<usize> {
        if self.block_count >= MAX_XATTR_BLOCKS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.block_count;
        self.blocks[idx].load_decompressed(decompressed, disk_offset, compressed_size)?;
        self.block_count += 1;
        Ok(idx)
    }

    /// Find a cached block by its disk offset.
    pub fn find_block(&self, disk_offset: u64) -> Option<&XattrBlock> {
        self.blocks[..self.block_count]
            .iter()
            .find(|b| b.loaded && b.disk_offset == disk_offset)
    }

    /// Parse xattr entries from a loaded block at the given byte offset.
    ///
    /// Reads up to `max_entries` entries starting at `offset` within the
    /// block.  Returns the entries and the number actually parsed.
    pub fn parse_entries(
        &self,
        block_idx: usize,
        offset: usize,
        max_entries: usize,
        out: &mut [XattrEntry],
    ) -> Result<usize> {
        if block_idx >= self.block_count || !self.blocks[block_idx].loaded {
            return Err(Error::NotFound);
        }
        let block = &self.blocks[block_idx];
        let limit = max_entries.min(out.len()).min(MAX_XATTRS_PER_INODE);
        let mut pos = offset;
        let mut count = 0;

        while count < limit {
            // Each on-disk entry: u16 type, u16 name_size, <name>,
            //                     u32 value_size, <value>
            if pos + 4 > block.data_len {
                break;
            }
            let raw_type = block.read_u16(pos)?;
            let name_size = block.read_u16(pos + 2)? as usize;
            pos += 4;

            if name_size > MAX_XATTR_NAME || pos + name_size > block.data_len {
                break;
            }
            let name = block.read_bytes(pos, name_size)?;
            pos += name_size;

            if pos + 4 > block.data_len {
                break;
            }
            let value_size = block.read_u32(pos)? as usize;
            pos += 4;

            // Bit 8 of type indicates out-of-line value.
            let ool = (raw_type & 0x100) != 0;
            let ns_type = XattrType::from_u16(raw_type & 0xFF).ok_or(Error::InvalidArgument)?;

            if value_size > MAX_XATTR_VALUE || pos + value_size > block.data_len {
                break;
            }
            let value = block.read_bytes(pos, value_size)?;
            pos += value_size;

            out[count] = XattrEntry::new(ns_type, name, value, ool)?;
            count += 1;
        }

        Ok(count)
    }

    /// Look up a specific xattr by full name for an inode.
    ///
    /// Returns a copy of the matching entry, or `NotFound` if the inode
    /// has no such attribute.
    pub fn lookup(&self, inode: u64, full_name: &[u8]) -> Result<XattrEntry> {
        let index = self.find_index(inode).ok_or(Error::NotFound)?;

        // Find the block containing this inode's xattrs.
        let block_idx = self.blocks[..self.block_count]
            .iter()
            .position(|b| {
                b.loaded
                    && b.disk_offset <= index.offset
                    && index.offset < b.disk_offset + b.data_len as u64
            })
            .ok_or(Error::NotFound)?;

        let base_offset = (index.offset - self.blocks[block_idx].disk_offset) as usize;
        let mut entries = [const { XattrEntry::empty() }; MAX_XATTRS_PER_INODE];
        let count =
            self.parse_entries(block_idx, base_offset, index.count as usize, &mut entries)?;

        for entry in &entries[..count] {
            if entry.matches_full_name(full_name) {
                return Ok(entry.clone());
            }
        }

        Err(Error::NotFound)
    }

    /// List all xattr names for an inode.
    ///
    /// Writes full names (with namespace prefix) into `buf`, separated by
    /// null bytes.  Returns the total number of bytes written.
    pub fn list(&self, inode: u64, buf: &mut [u8]) -> Result<usize> {
        let index = self.find_index(inode).ok_or(Error::NotFound)?;

        let block_idx = self.blocks[..self.block_count]
            .iter()
            .position(|b| {
                b.loaded
                    && b.disk_offset <= index.offset
                    && index.offset < b.disk_offset + b.data_len as u64
            })
            .ok_or(Error::NotFound)?;

        let base_offset = (index.offset - self.blocks[block_idx].disk_offset) as usize;
        let mut entries = [const { XattrEntry::empty() }; MAX_XATTRS_PER_INODE];
        let count =
            self.parse_entries(block_idx, base_offset, index.count as usize, &mut entries)?;

        let mut pos = 0;
        let buf_len = buf.len();
        for entry in &entries[..count] {
            let prefix = entry.xattr_type.prefix();
            let name_len = prefix.len() + entry.name_bytes().len();
            let needed = name_len + 1; // +1 for null terminator
            if pos + needed > buf_len {
                return Err(Error::InvalidArgument);
            }
            buf[pos..pos + prefix.len()].copy_from_slice(prefix);
            buf[pos + prefix.len()..pos + name_len].copy_from_slice(entry.name_bytes());
            buf[pos + name_len] = 0;
            pos += needed;
        }

        Ok(pos)
    }

    /// Return the number of registered xattr index entries.
    pub fn index_count(&self) -> usize {
        self.index_count
    }

    /// Return the number of loaded xattr blocks.
    pub fn block_count(&self) -> usize {
        self.block_count
    }

    /// Check whether xattrs are present for the given inode.
    pub fn has_xattrs(&self, inode: u64) -> bool {
        self.find_index(inode).is_some()
    }
}

impl Default for SquashfsXattr {
    fn default() -> Self {
        Self::new(0, 0)
    }
}
