// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! XFS-style inode management with B+ tree extent allocation.
//!
//! This module provides dedicated inode management facilities for XFS
//! filesystems, complementing the read-only driver in [`crate::xfs`].
//! It implements inode creation, modification, and the data-fork
//! abstraction (inline, extent list, B+ tree) that XFS uses to map
//! file data to physical blocks.
//!
//! # Architecture
//!
//! ```text
//! XfsInodeManager
//!   ├── InodeTable[0..MAX_INODES]  — per-inode metadata
//!   │     └── InodeFork
//!   │           ├── Inline  — small data stored in the inode itself
//!   │           ├── Extents — XfsExtent list (up to MAX_EXTENTS_PER_INODE)
//!   │           └── BTree   — B+ tree root for large files
//!   └── InodeAllocator        — free inode tracking
//! ```
//!
//! # Inode Fork Formats
//!
//! XFS stores file data references in a "fork" that can take three
//! forms depending on the amount of data:
//!
//! - **Inline**: Data stored directly in the inode (short symlinks,
//!   small directories, tiny files).
//! - **Extents**: An array of [`XfsExtent`] records mapping logical
//!   file offsets to physical blocks.
//! - **BTree**: A B+ tree of extent records for files with many
//!   extents.
//!
//! # References
//!
//! - XFS on-disk format specification (Chapter 7: Inodes)
//! - Linux `fs/xfs/libxfs/xfs_inode_fork.c`
//! - Linux `fs/xfs/libxfs/xfs_bmap.c`

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Maximum number of inodes in the inode table.
const MAX_INODES: usize = 1024;

/// Maximum extents per inode in extent-format fork.
const MAX_EXTENTS_PER_INODE: usize = 32;

/// Maximum inline data bytes stored within an inode.
const MAX_INLINE_DATA: usize = 64;

/// Maximum keys per B+ tree node in the extent tree.
const MAX_BTREE_KEYS: usize = 32;

/// Maximum B+ tree nodes per inode.
const MAX_BTREE_NODES: usize = 8;

/// XFS inode magic number: "IN" = 0x494E.
const XFS_DI_MAGIC: u16 = 0x494E;

/// Inode type mask (upper 4 bits of mode).
const S_IFMT: u16 = 0xF000;
/// Regular file type.
const S_IFREG: u16 = 0x8000;
/// Directory type.
const S_IFDIR: u16 = 0x4000;
/// Symbolic link type.
const S_IFLNK: u16 = 0xA000;
/// Block device type.
const S_IFBLK: u16 = 0x6000;
/// Character device type.
const S_IFCHR: u16 = 0x2000;
/// FIFO (named pipe) type.
const S_IFIFO: u16 = 0x1000;
/// Socket type.
const S_IFSOCK: u16 = 0xC000;

// ── InodeFormat ─────────────────────────────────────────────────

/// Inode data fork format, matching the XFS on-disk `di_format` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeFormat {
    /// Data stored inline in the inode body.
    Local,
    /// Data addressed via extent records.
    Extents,
    /// Data addressed via a B+ tree of extent records.
    BTree,
}

impl InodeFormat {
    /// Parse from the on-disk u8 format field.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Local),
            2 => Some(Self::Extents),
            3 => Some(Self::BTree),
            _ => None,
        }
    }

    /// Return the on-disk format value.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Local => 1,
            Self::Extents => 2,
            Self::BTree => 3,
        }
    }
}

// ── XfsExtent ───────────────────────────────────────────────────

/// An extent record mapping logical file blocks to physical blocks.
///
/// Each extent is a contiguous range of blocks. The `startoff` field
/// gives the logical offset within the file (in filesystem blocks),
/// and `startblock` gives the corresponding physical block number.
#[derive(Debug, Clone, Copy)]
pub struct XfsExtent {
    /// Logical file offset in filesystem blocks.
    pub startoff: u64,
    /// Physical starting block number.
    pub startblock: u64,
    /// Number of contiguous blocks.
    pub blockcount: u32,
    /// Extent state flags (0 = written, 1 = unwritten/preallocated).
    pub state: u8,
    /// Whether this slot is active.
    pub active: bool,
}

impl XfsExtent {
    /// Create an empty (inactive) extent slot.
    pub const fn empty() -> Self {
        Self {
            startoff: 0,
            startblock: 0,
            blockcount: 0,
            state: 0,
            active: false,
        }
    }

    /// Create a new extent.
    pub fn new(startoff: u64, startblock: u64, blockcount: u32) -> Self {
        Self {
            startoff,
            startblock,
            blockcount,
            state: 0,
            active: true,
        }
    }

    /// Whether this extent contains the given logical block offset.
    pub fn contains(&self, logical_block: u64) -> bool {
        self.active
            && logical_block >= self.startoff
            && logical_block < self.startoff + self.blockcount as u64
    }

    /// Translate a logical block to a physical block.
    pub fn translate(&self, logical_block: u64) -> Option<u64> {
        if self.contains(logical_block) {
            Some(self.startblock + (logical_block - self.startoff))
        } else {
            None
        }
    }

    /// End offset (exclusive) of this extent in logical blocks.
    pub fn end_offset(&self) -> u64 {
        self.startoff + self.blockcount as u64
    }

    /// Whether this extent represents a preallocated (unwritten) range.
    pub fn is_unwritten(&self) -> bool {
        self.state == 1
    }
}

// ── InodeFork ───────────────────────────────────────────────────

/// Inode data fork holding file content references.
///
/// The fork format determines how data is stored:
/// - `Local`: inline data array
/// - `Extents`: fixed-size extent list
/// - `BTree`: B+ tree root (stub — uses extent list internally)
#[derive(Debug, Clone)]
pub struct InodeFork {
    /// Fork format.
    pub format: InodeFormat,
    /// Inline data (valid when format == Local).
    pub inline_data: [u8; MAX_INLINE_DATA],
    /// Inline data length.
    pub inline_len: usize,
    /// Extent list (valid when format == Extents or BTree).
    pub extents: [XfsExtent; MAX_EXTENTS_PER_INODE],
    /// Number of active extents.
    pub extent_count: usize,
}

impl InodeFork {
    /// Create a new empty fork in local (inline) format.
    pub fn new_local() -> Self {
        Self {
            format: InodeFormat::Local,
            inline_data: [0u8; MAX_INLINE_DATA],
            inline_len: 0,
            extents: [const { XfsExtent::empty() }; MAX_EXTENTS_PER_INODE],
            extent_count: 0,
        }
    }

    /// Create a new empty fork in extents format.
    pub fn new_extents() -> Self {
        Self {
            format: InodeFormat::Extents,
            inline_data: [0u8; MAX_INLINE_DATA],
            inline_len: 0,
            extents: [const { XfsExtent::empty() }; MAX_EXTENTS_PER_INODE],
            extent_count: 0,
        }
    }

    /// Set inline data.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the data exceeds [`MAX_INLINE_DATA`].
    pub fn set_inline(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > MAX_INLINE_DATA {
            return Err(Error::InvalidArgument);
        }
        self.format = InodeFormat::Local;
        self.inline_data[..data.len()].copy_from_slice(data);
        self.inline_len = data.len();
        Ok(())
    }

    /// Read inline data into `buf`, returning bytes copied.
    pub fn read_inline(&self, offset: usize, buf: &mut [u8]) -> usize {
        if self.format != InodeFormat::Local || offset >= self.inline_len {
            return 0;
        }
        let available = self.inline_len - offset;
        let to_copy = buf.len().min(available);
        buf[..to_copy].copy_from_slice(&self.inline_data[offset..offset + to_copy]);
        to_copy
    }

    /// Add an extent to the fork.
    ///
    /// # Errors
    ///
    /// Returns `OutOfMemory` if the extent list is full.
    pub fn add_extent(&mut self, extent: XfsExtent) -> Result<()> {
        if self.extent_count >= MAX_EXTENTS_PER_INODE {
            return Err(Error::OutOfMemory);
        }
        // Insert in sorted order by startoff.
        let mut pos = self.extent_count;
        for (i, e) in self.extents[..self.extent_count].iter().enumerate() {
            if e.startoff > extent.startoff {
                pos = i;
                break;
            }
        }
        // Shift right.
        for i in (pos..self.extent_count).rev() {
            self.extents[i + 1] = self.extents[i];
        }
        self.extents[pos] = extent;
        self.extent_count += 1;
        if self.format == InodeFormat::Local {
            self.format = InodeFormat::Extents;
        }
        Ok(())
    }

    /// Look up the physical block for a logical file block.
    pub fn translate_block(&self, logical_block: u64) -> Option<u64> {
        for extent in &self.extents[..self.extent_count] {
            if let Some(phys) = extent.translate(logical_block) {
                return Some(phys);
            }
        }
        None
    }

    /// Total number of blocks covered by all extents.
    pub fn total_blocks(&self) -> u64 {
        self.extents[..self.extent_count]
            .iter()
            .map(|e| e.blockcount as u64)
            .sum()
    }

    /// Promote from extents format to B+ tree format.
    ///
    /// This is a logical promotion only; the extent data remains the
    /// same but the format tag changes to indicate that a B+ tree
    /// should be used for lookups on large files.
    pub fn promote_to_btree(&mut self) {
        if self.format == InodeFormat::Extents {
            self.format = InodeFormat::BTree;
        }
    }
}

// ── XfsInode ────────────────────────────────────────────────────

/// XFS inode with full metadata and data fork.
///
/// This is the in-memory representation of an XFS inode. It includes
/// all core fields (mode, uid, gid, times, size, nlink) and the
/// data fork which holds file content references.
#[derive(Debug, Clone)]
pub struct XfsInode {
    /// Inode number.
    pub ino: u64,
    /// Magic number (should be [`XFS_DI_MAGIC`]).
    pub di_magic: u16,
    /// File mode (type + permission bits).
    pub di_mode: u16,
    /// Owner user ID.
    pub di_uid: u32,
    /// Owner group ID.
    pub di_gid: u32,
    /// Hard link count.
    pub di_nlink: u32,
    /// File size in bytes.
    pub di_size: u64,
    /// Last access time (seconds since epoch).
    pub di_atime: u64,
    /// Last modification time (seconds since epoch).
    pub di_mtime: u64,
    /// Last inode change time (seconds since epoch).
    pub di_ctime: u64,
    /// Number of filesystem blocks allocated.
    pub di_nblocks: u64,
    /// Data fork.
    pub data_fork: InodeFork,
    /// Generation number (NFS handle validation).
    pub di_generation: u32,
    /// Whether this inode slot is active.
    pub active: bool,
}

impl XfsInode {
    /// Create an empty (inactive) inode slot.
    pub fn empty() -> Self {
        Self {
            ino: 0,
            di_magic: 0,
            di_mode: 0,
            di_uid: 0,
            di_gid: 0,
            di_nlink: 0,
            di_size: 0,
            di_atime: 0,
            di_mtime: 0,
            di_ctime: 0,
            di_nblocks: 0,
            data_fork: InodeFork::new_local(),
            di_generation: 0,
            active: false,
        }
    }

    /// Create a new regular file inode.
    pub fn new_file(ino: u64, mode: u16, uid: u32, gid: u32) -> Self {
        Self {
            ino,
            di_magic: XFS_DI_MAGIC,
            di_mode: S_IFREG | (mode & 0x0FFF),
            di_uid: uid,
            di_gid: gid,
            di_nlink: 1,
            di_size: 0,
            di_atime: 0,
            di_mtime: 0,
            di_ctime: 0,
            di_nblocks: 0,
            data_fork: InodeFork::new_extents(),
            di_generation: 1,
            active: true,
        }
    }

    /// Create a new directory inode.
    pub fn new_dir(ino: u64, mode: u16, uid: u32, gid: u32) -> Self {
        Self {
            ino,
            di_magic: XFS_DI_MAGIC,
            di_mode: S_IFDIR | (mode & 0x0FFF),
            di_uid: uid,
            di_gid: gid,
            di_nlink: 2,
            di_size: 0,
            di_atime: 0,
            di_mtime: 0,
            di_ctime: 0,
            di_nblocks: 0,
            data_fork: InodeFork::new_local(),
            di_generation: 1,
            active: true,
        }
    }

    /// Create a new symlink inode.
    pub fn new_symlink(ino: u64, mode: u16, uid: u32, gid: u32) -> Self {
        Self {
            ino,
            di_magic: XFS_DI_MAGIC,
            di_mode: S_IFLNK | (mode & 0x0FFF),
            di_uid: uid,
            di_gid: gid,
            di_nlink: 1,
            di_size: 0,
            di_atime: 0,
            di_mtime: 0,
            di_ctime: 0,
            di_nblocks: 0,
            data_fork: InodeFork::new_local(),
            di_generation: 1,
            active: true,
        }
    }

    /// Whether this is a regular file.
    pub fn is_file(&self) -> bool {
        self.di_mode & S_IFMT == S_IFREG
    }

    /// Whether this is a directory.
    pub fn is_dir(&self) -> bool {
        self.di_mode & S_IFMT == S_IFDIR
    }

    /// Whether this is a symbolic link.
    pub fn is_symlink(&self) -> bool {
        self.di_mode & S_IFMT == S_IFLNK
    }

    /// POSIX permission bits (lower 12 bits of mode).
    pub fn permissions(&self) -> u16 {
        self.di_mode & 0x0FFF
    }

    /// File type bits (upper 4 bits of mode).
    pub fn file_type_bits(&self) -> u16 {
        self.di_mode & S_IFMT
    }

    /// Data fork format.
    pub fn fork_format(&self) -> InodeFormat {
        self.data_fork.format
    }

    /// Update all three timestamps to the given value.
    pub fn touch(&mut self, now: u64) {
        self.di_atime = now;
        self.di_mtime = now;
        self.di_ctime = now;
    }

    /// Increment the hard link count.
    pub fn link(&mut self) {
        self.di_nlink = self.di_nlink.saturating_add(1);
    }

    /// Decrement the hard link count; returns `true` if it reached zero.
    pub fn unlink(&mut self) -> bool {
        self.di_nlink = self.di_nlink.saturating_sub(1);
        self.di_nlink == 0
    }
}

// ── InodeAllocator ──────────────────────────────────────────────

/// Bitmap-based inode allocator for a fixed inode table.
///
/// Tracks which inode numbers are in use via a simple bitmap.
/// Allocation scans for the first free bit.
pub struct InodeAllocator {
    /// Bitmap: each bit represents one inode (1 = in use).
    bitmap: [u64; MAX_INODES / 64],
    /// Total number of allocated inodes.
    allocated: usize,
    /// Next inode number to start scanning from.
    next_hint: u64,
}

impl InodeAllocator {
    /// Create a new allocator with no inodes allocated.
    pub fn new() -> Self {
        Self {
            bitmap: [0u64; MAX_INODES / 64],
            allocated: 0,
            next_hint: 1, // inode 0 is reserved
        }
    }

    /// Allocate the next available inode number.
    ///
    /// # Errors
    ///
    /// Returns `OutOfMemory` if no inode numbers are available.
    pub fn allocate(&mut self) -> Result<u64> {
        let start = self.next_hint as usize;
        for offset in 0..MAX_INODES {
            let ino = (start + offset) % MAX_INODES;
            if ino == 0 {
                continue; // inode 0 reserved
            }
            let word = ino / 64;
            let bit = ino % 64;
            if self.bitmap[word] & (1u64 << bit) == 0 {
                self.bitmap[word] |= 1u64 << bit;
                self.allocated += 1;
                self.next_hint = (ino + 1) as u64;
                return Ok(ino as u64);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Free an inode number.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the inode was not allocated.
    pub fn free(&mut self, ino: u64) -> Result<()> {
        let idx = ino as usize;
        if idx == 0 || idx >= MAX_INODES {
            return Err(Error::InvalidArgument);
        }
        let word = idx / 64;
        let bit = idx % 64;
        if self.bitmap[word] & (1u64 << bit) == 0 {
            return Err(Error::NotFound);
        }
        self.bitmap[word] &= !(1u64 << bit);
        self.allocated = self.allocated.saturating_sub(1);
        Ok(())
    }

    /// Whether the given inode number is allocated.
    pub fn is_allocated(&self, ino: u64) -> bool {
        let idx = ino as usize;
        if idx >= MAX_INODES {
            return false;
        }
        let word = idx / 64;
        let bit = idx % 64;
        self.bitmap[word] & (1u64 << bit) != 0
    }

    /// Number of allocated inodes.
    pub fn count(&self) -> usize {
        self.allocated
    }

    /// Number of free inodes.
    pub fn free_count(&self) -> usize {
        MAX_INODES.saturating_sub(self.allocated + 1) // -1 for reserved ino 0
    }
}

impl Default for InodeAllocator {
    fn default() -> Self {
        Self::new()
    }
}

// ── XfsInodeManager ─────────────────────────────────────────────

/// XFS inode management subsystem.
///
/// Provides inode allocation, creation, lookup, modification, and
/// extent management. The inode table is fixed-size (no heap).
pub struct XfsInodeManager {
    /// Inode table.
    inodes: [Option<XfsInode>; MAX_INODES],
    /// Inode allocator (bitmap).
    allocator: InodeAllocator,
    /// Next physical block for extent allocation.
    next_block: u64,
    /// Filesystem block size in bytes.
    block_size: u32,
}

impl XfsInodeManager {
    /// Create a new inode manager.
    ///
    /// Allocates inode 1 as the root directory.
    pub fn new(block_size: u32) -> Result<Self> {
        const NONE: Option<XfsInode> = None;
        let mut mgr = Self {
            inodes: [NONE; MAX_INODES],
            allocator: InodeAllocator::new(),
            next_block: 0,
            block_size,
        };

        // Allocate root directory at inode 1.
        let root_ino = mgr.allocator.allocate()?;
        debug_assert_eq!(root_ino, 1);
        mgr.inodes[root_ino as usize] = Some(XfsInode::new_dir(root_ino, 0o755, 0, 0));
        Ok(mgr)
    }

    /// Create a new regular file inode.
    pub fn create_file(&mut self, mode: u16, uid: u32, gid: u32) -> Result<u64> {
        let ino = self.allocator.allocate()?;
        self.inodes[ino as usize] = Some(XfsInode::new_file(ino, mode, uid, gid));
        Ok(ino)
    }

    /// Create a new directory inode.
    pub fn create_dir(&mut self, mode: u16, uid: u32, gid: u32) -> Result<u64> {
        let ino = self.allocator.allocate()?;
        self.inodes[ino as usize] = Some(XfsInode::new_dir(ino, mode, uid, gid));
        Ok(ino)
    }

    /// Create a new symlink inode.
    pub fn create_symlink(&mut self, mode: u16, uid: u32, gid: u32, target: &[u8]) -> Result<u64> {
        let ino = self.allocator.allocate()?;
        let mut inode = XfsInode::new_symlink(ino, mode, uid, gid);
        inode.data_fork.set_inline(target)?;
        inode.di_size = target.len() as u64;
        self.inodes[ino as usize] = Some(inode);
        Ok(ino)
    }

    /// Look up an inode by number.
    pub fn get(&self, ino: u64) -> Result<&XfsInode> {
        let idx = ino as usize;
        if idx >= MAX_INODES {
            return Err(Error::InvalidArgument);
        }
        match &self.inodes[idx] {
            Some(inode) if inode.active => Ok(inode),
            _ => Err(Error::NotFound),
        }
    }

    /// Get a mutable reference to an inode.
    pub fn get_mut(&mut self, ino: u64) -> Result<&mut XfsInode> {
        let idx = ino as usize;
        if idx >= MAX_INODES {
            return Err(Error::InvalidArgument);
        }
        match &mut self.inodes[idx] {
            Some(inode) if inode.active => Ok(inode),
            _ => Err(Error::NotFound),
        }
    }

    /// Free an inode, releasing its number back to the allocator.
    pub fn free_inode(&mut self, ino: u64) -> Result<()> {
        let idx = ino as usize;
        if idx >= MAX_INODES {
            return Err(Error::InvalidArgument);
        }
        match &self.inodes[idx] {
            Some(inode) if inode.active => {}
            _ => return Err(Error::NotFound),
        }
        self.inodes[idx] = None;
        self.allocator.free(ino)
    }

    /// Allocate a physical extent for a file inode.
    ///
    /// Adds a new extent of `block_count` blocks to the inode's
    /// data fork. The physical blocks are allocated sequentially
    /// from the allocator's next-block counter.
    pub fn allocate_extent(&mut self, ino: u64, block_count: u32) -> Result<XfsExtent> {
        // Pre-compute allocator state before borrowing inode.
        let startblock = self.next_block;
        let block_size = self.block_size;

        let idx = ino as usize;
        if idx >= MAX_INODES {
            return Err(Error::InvalidArgument);
        }
        let inode = match &mut self.inodes[idx] {
            Some(inode) if inode.active => inode,
            _ => return Err(Error::NotFound),
        };
        if !inode.is_file() {
            return Err(Error::InvalidArgument);
        }
        let startoff = inode.data_fork.total_blocks();
        let extent = XfsExtent::new(startoff, startblock, block_count);
        inode.data_fork.add_extent(extent)?;
        inode.di_nblocks = inode.di_nblocks.saturating_add(block_count as u64);
        inode.di_size = inode.di_nblocks * block_size as u64;

        self.next_block = startblock.saturating_add(block_count as u64);
        Ok(extent)
    }

    /// Truncate a file inode to zero length.
    ///
    /// Removes all extents and resets the file size. Does not
    /// reclaim physical blocks (they become unreferenced).
    pub fn truncate(&mut self, ino: u64) -> Result<()> {
        let inode = self.get_mut(ino)?;
        if !inode.is_file() {
            return Err(Error::InvalidArgument);
        }
        inode.data_fork = InodeFork::new_extents();
        inode.di_size = 0;
        inode.di_nblocks = 0;
        Ok(())
    }

    /// Update the file size of an inode (for writes beyond current EOF).
    pub fn update_size(&mut self, ino: u64, new_size: u64) -> Result<()> {
        let inode = self.get_mut(ino)?;
        inode.di_size = new_size;
        Ok(())
    }

    /// Update modification time.
    pub fn update_mtime(&mut self, ino: u64, now: u64) -> Result<()> {
        let inode = self.get_mut(ino)?;
        inode.di_mtime = now;
        inode.di_ctime = now;
        Ok(())
    }

    /// Change ownership of an inode.
    pub fn chown(&mut self, ino: u64, uid: u32, gid: u32) -> Result<()> {
        let inode = self.get_mut(ino)?;
        inode.di_uid = uid;
        inode.di_gid = gid;
        Ok(())
    }

    /// Change permissions of an inode.
    pub fn chmod(&mut self, ino: u64, mode: u16) -> Result<()> {
        let inode = self.get_mut(ino)?;
        let file_type = inode.di_mode & S_IFMT;
        inode.di_mode = file_type | (mode & 0x0FFF);
        Ok(())
    }

    /// Number of allocated inodes.
    pub fn inode_count(&self) -> usize {
        self.allocator.count()
    }

    /// Number of free inode slots.
    pub fn free_inodes(&self) -> usize {
        self.allocator.free_count()
    }

    /// Block size in bytes.
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Root directory inode number.
    pub fn root_ino(&self) -> u64 {
        1
    }
}
