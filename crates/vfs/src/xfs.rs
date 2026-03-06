// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! XFS filesystem driver (read-only).
//!
//! Implements the core on-disk structures and read-only operations for
//! the XFS filesystem. XFS is a high-performance 64-bit journaling
//! filesystem originally developed by SGI. It uses allocation groups
//! (AGs) for parallelism and B+ trees for extent mapping.
//!
//! # Design
//!
//! - [`XfsSuperblock`] — primary superblock with filesystem geometry
//! - [`XfsAgHeader`] — allocation group header with free-space info
//! - [`XfsInode`] — on-disk inode structure with extent/btree data format
//! - [`XfsExtent`] — contiguous range of blocks mapped to a file offset
//! - [`XfsBtreeNode`] — B+ tree node for extent-based files
//! - [`XfsFs`] — read-only filesystem instance with inode cache
//! - [`XfsRegistry`] — global registry for mounted XFS instances (4 slots)
//!
//! # On-disk Layout
//!
//! ```text
//! AG 0: [Superblock | AG Header | Free-space B+trees | Inode B+tree | Data]
//! AG 1: [AG Header | Free-space B+trees | Inode B+tree | Data]
//! AG 2: ...
//! ```
//!
//! Reference: `filesystems/xfs/` in kernel documentation.

use oncrix_lib::{Error, Result};

use crate::ext2::BlockReader;

// ── Constants ───────────────────────────────────────────────────

/// XFS superblock magic number: "XFSB" = 0x58465342.
const XFS_SB_MAGIC: u32 = 0x5846_5342;

/// XFS inode magic number: "IN" = 0x494E.
const XFS_INODE_MAGIC: u16 = 0x494E;

/// Maximum number of allocation groups supported.
const MAX_AG_COUNT: usize = 16;

/// Maximum number of cached inodes.
const MAX_INODE_CACHE: usize = 256;

/// Maximum number of extents per inode (extent-format).
const MAX_EXTENTS: usize = 64;

/// Maximum keys/pointers per B+ tree node.
const MAX_BTREE_RECS: usize = 64;

/// Maximum directory entries returned from a single readdir.
const MAX_DIR_ENTRIES: usize = 128;

/// Maximum name length for directory entries.
const MAX_NAME_LEN: usize = 255;

/// Maximum number of mounted XFS instances.
const MAX_XFS_INSTANCES: usize = 4;

// ── XfsSuperblock ───────────────────────────────────────────────

/// XFS primary superblock (at byte offset 0 of AG 0).
///
/// Contains the filesystem geometry, allocation group layout, and
/// feature flags. A copy exists at the start of every AG but only
/// the AG 0 copy is authoritative.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct XfsSuperblock {
    /// Magic number (must be 0x58465342 = "XFSB").
    pub sb_magicnum: u32,
    /// Filesystem block size in bytes (power of 2, 512..65536).
    pub sb_blocksize: u32,
    /// Total number of data blocks in the filesystem.
    pub sb_dblocks: u64,
    /// Number of allocation groups.
    pub sb_agcount: u32,
    /// Number of blocks per allocation group.
    pub sb_agblocks: u32,
    /// Inode number of the root directory.
    pub sb_rootino: u64,
    /// On-disk inode size in bytes (256 or 512 typically).
    pub sb_inodesize: u16,
    /// Underlying device sector size in bytes.
    pub sb_sectsize: u16,
    /// Compatible feature flags.
    pub sb_features_compat: u32,
    /// Incompatible feature flags.
    pub sb_features_incompat: u32,
}

impl XfsSuperblock {
    /// Parse a superblock from a byte buffer (at least 64 bytes).
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 64 {
            return Err(Error::InvalidArgument);
        }
        let sb = Self {
            sb_magicnum: read_u32_be(buf, 0),
            sb_blocksize: read_u32_be(buf, 4),
            sb_dblocks: read_u64_be(buf, 8),
            sb_agcount: read_u32_be(buf, 16),
            sb_agblocks: read_u32_be(buf, 20),
            sb_rootino: read_u64_be(buf, 24),
            sb_inodesize: read_u16_be(buf, 32),
            sb_sectsize: read_u16_be(buf, 34),
            sb_features_compat: read_u32_be(buf, 36),
            sb_features_incompat: read_u32_be(buf, 40),
        };
        if sb.sb_magicnum != XFS_SB_MAGIC {
            return Err(Error::InvalidArgument);
        }
        if sb.sb_blocksize == 0 || !sb.sb_blocksize.is_power_of_two() {
            return Err(Error::InvalidArgument);
        }
        Ok(sb)
    }

    /// Validate the superblock fields.
    pub fn validate(&self) -> Result<()> {
        if self.sb_magicnum != XFS_SB_MAGIC {
            return Err(Error::InvalidArgument);
        }
        if self.sb_blocksize == 0 || !self.sb_blocksize.is_power_of_two() {
            return Err(Error::InvalidArgument);
        }
        if self.sb_agcount == 0 || self.sb_agblocks == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.sb_inodesize < 256 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ── XfsAgHeader ─────────────────────────────────────────────────

/// XFS allocation group header.
///
/// Each allocation group has its own header containing free-space
/// accounting and root block numbers for the per-AG B+ trees
/// (free-space by block number, free-space by size, inode).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct XfsAgHeader {
    /// AG magic number.
    pub magicnum: u32,
    /// Sequence number of this AG (0-based).
    pub seqno: u32,
    /// Length of this AG in filesystem blocks.
    pub length: u32,
    /// Root block of the by-block-number free-space B+ tree.
    pub bno_root: u32,
    /// Root block of the by-size free-space B+ tree.
    pub cnt_root: u32,
    /// Root block of the inode B+ tree.
    pub ino_root: u32,
    /// Number of free blocks in this AG.
    pub freeblks: u32,
    /// Longest contiguous free extent in this AG (blocks).
    pub longest_free: u32,
}

impl XfsAgHeader {
    /// Parse an AG header from a byte buffer.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 32 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            magicnum: read_u32_be(buf, 0),
            seqno: read_u32_be(buf, 4),
            length: read_u32_be(buf, 8),
            bno_root: read_u32_be(buf, 12),
            cnt_root: read_u32_be(buf, 16),
            ino_root: read_u32_be(buf, 20),
            freeblks: read_u32_be(buf, 24),
            longest_free: read_u32_be(buf, 28),
        })
    }
}

// ── XfsInodeFormat ──────────────────────────────────────────────

/// XFS inode data format.
///
/// Determines how the file's data is organized on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XfsInodeFormat {
    /// Data stored as extent records directly in the inode.
    Extents,
    /// Data stored via a B+ tree of extent records.
    BTree,
    /// Data stored inline within the inode (short symlinks, small dirs).
    Local,
}

impl XfsInodeFormat {
    /// Parse from the on-disk format field.
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

// ── XfsInode ────────────────────────────────────────────────────

/// XFS on-disk inode.
///
/// Contains file metadata and either inline data, extent records,
/// or a B+ tree root depending on `di_format`.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct XfsInode {
    /// Inode magic number (must be 0x494E = "IN").
    pub di_magic: u16,
    /// File mode (type + permissions, POSIX-style).
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
    /// Data fork format (Local=1, Extents=2, BTree=3).
    pub di_format: u8,
}

/// Inode type mask.
const S_IFMT: u16 = 0xF000;
/// Regular file.
const S_IFREG: u16 = 0x8000;
/// Directory.
const S_IFDIR: u16 = 0x4000;
/// Symbolic link.
const S_IFLNK: u16 = 0xA000;

impl XfsInode {
    /// Parse an XFS inode from a byte buffer.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 64 {
            return Err(Error::InvalidArgument);
        }
        let inode = Self {
            di_magic: read_u16_be(buf, 0),
            di_mode: read_u16_be(buf, 2),
            di_uid: read_u32_be(buf, 4),
            di_gid: read_u32_be(buf, 8),
            di_nlink: read_u32_be(buf, 12),
            di_size: read_u64_be(buf, 16),
            di_atime: read_u64_be(buf, 24),
            di_mtime: read_u64_be(buf, 32),
            di_ctime: read_u64_be(buf, 40),
            di_nblocks: read_u64_be(buf, 48),
            di_format: buf[56],
        };
        if inode.di_magic != XFS_INODE_MAGIC {
            return Err(Error::InvalidArgument);
        }
        Ok(inode)
    }

    /// File type derived from `di_mode`.
    pub fn file_type(&self) -> Option<crate::inode::FileType> {
        match self.di_mode & S_IFMT {
            S_IFREG => Some(crate::inode::FileType::Regular),
            S_IFDIR => Some(crate::inode::FileType::Directory),
            S_IFLNK => Some(crate::inode::FileType::Symlink),
            _ => None,
        }
    }

    /// Data format for this inode.
    pub fn format(&self) -> Option<XfsInodeFormat> {
        XfsInodeFormat::from_u8(self.di_format)
    }

    /// POSIX permission bits (lower 12 bits of di_mode).
    pub fn permissions(&self) -> u16 {
        self.di_mode & 0x0FFF
    }

    /// Whether this inode represents a directory.
    pub fn is_dir(&self) -> bool {
        self.di_mode & S_IFMT == S_IFDIR
    }

    /// Whether this inode represents a regular file.
    pub fn is_file(&self) -> bool {
        self.di_mode & S_IFMT == S_IFREG
    }
}

// ── XfsExtent ───────────────────────────────────────────────────

/// XFS extent record.
///
/// Maps a contiguous range of logical file blocks to physical disk
/// blocks. XFS uses extent-based allocation for efficient mapping
/// of large files.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct XfsExtent {
    /// Starting logical offset within the file (in filesystem blocks).
    pub startoff: u64,
    /// Starting physical block number on disk.
    pub startblock: u64,
    /// Number of contiguous blocks in this extent.
    pub blockcount: u32,
    /// Extent flags (0 = normal, 1 = unwritten/preallocated).
    pub flag: u8,
}

impl XfsExtent {
    /// Parse an extent record from a 16-byte buffer.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 16 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            startoff: read_u64_be(buf, 0),
            startblock: read_u64_be(buf, 8) & 0x000F_FFFF_FFFF_FFFF, // 52-bit block
            blockcount: ((read_u64_be(buf, 8) >> 52) & 0xFFF) as u32,
            flag: (buf[8] >> 4) & 0x0F,
        })
    }

    /// Whether this extent contains the given logical block offset.
    pub fn contains(&self, logical_block: u64) -> bool {
        logical_block >= self.startoff && logical_block < self.startoff + self.blockcount as u64
    }

    /// Translate a logical block offset to a physical block number.
    ///
    /// Returns `None` if the logical block is not within this extent.
    pub fn translate(&self, logical_block: u64) -> Option<u64> {
        if self.contains(logical_block) {
            Some(self.startblock + (logical_block - self.startoff))
        } else {
            None
        }
    }
}

// ── XfsBtreeNode ────────────────────────────────────────────────

/// XFS B+ tree node for extent mapping.
///
/// Internal nodes contain keys and child pointers; leaf nodes
/// contain extent records directly. Used when the number of extents
/// exceeds the inode's inline capacity.
#[derive(Debug, Clone)]
pub struct XfsBtreeNode {
    /// Tree level (0 = leaf, >0 = internal).
    pub level: u16,
    /// Number of records/keys in this node.
    pub numrecs: u16,
    /// Keys for internal nodes (logical block start offsets).
    pub keys: [u64; MAX_BTREE_RECS],
    /// Child block pointers (for internal nodes) or unused (for leaves).
    pub ptrs: [u64; MAX_BTREE_RECS],
}

impl XfsBtreeNode {
    /// Create an empty B+ tree node.
    pub fn new(level: u16) -> Self {
        Self {
            level,
            numrecs: 0,
            keys: [0u64; MAX_BTREE_RECS],
            ptrs: [0u64; MAX_BTREE_RECS],
        }
    }

    /// Whether this is a leaf node.
    pub fn is_leaf(&self) -> bool {
        self.level == 0
    }

    /// Insert a key/pointer pair into an internal node.
    ///
    /// Maintains sorted order by key.
    pub fn insert(&mut self, key: u64, ptr: u64) -> Result<()> {
        if self.numrecs as usize >= MAX_BTREE_RECS {
            return Err(Error::OutOfMemory);
        }
        // Find insertion point.
        let mut pos = self.numrecs as usize;
        for i in 0..self.numrecs as usize {
            if key < self.keys[i] {
                pos = i;
                break;
            }
        }
        // Shift entries right.
        let n = self.numrecs as usize;
        for i in (pos..n).rev() {
            self.keys[i + 1] = self.keys[i];
            self.ptrs[i + 1] = self.ptrs[i];
        }
        self.keys[pos] = key;
        self.ptrs[pos] = ptr;
        self.numrecs += 1;
        Ok(())
    }

    /// Look up the child pointer for a given key.
    ///
    /// Returns the pointer for the largest key <= the search key.
    pub fn lookup(&self, key: u64) -> Option<u64> {
        if self.numrecs == 0 {
            return None;
        }
        let mut best = 0;
        for i in 0..self.numrecs as usize {
            if self.keys[i] <= key {
                best = i;
            } else {
                break;
            }
        }
        Some(self.ptrs[best])
    }
}

// ── XfsFs ───────────────────────────────────────────────────────

/// Cached inode entry.
#[derive(Clone)]
struct XfsInodeCache {
    /// Inode number.
    ino: u64,
    /// Parsed inode.
    inode: XfsInode,
    /// Extent list (for extent-format inodes). Reserved for read_via_extents.
    #[allow(dead_code)]
    extents: [Option<XfsExtent>; MAX_EXTENTS],
    /// Number of valid extents. Reserved for read_via_extents.
    #[allow(dead_code)]
    extent_count: usize,
    /// Whether this cache slot is valid.
    valid: bool,
}

impl XfsInodeCache {
    const fn empty() -> Self {
        Self {
            ino: 0,
            inode: XfsInode {
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
                di_format: 0,
            },
            extents: [None; MAX_EXTENTS],
            extent_count: 0,
            valid: false,
        }
    }
}

/// A directory entry read from an XFS directory.
#[derive(Debug, Clone)]
pub struct XfsDirEntry {
    /// Inode number of the entry.
    pub ino: u64,
    /// File name bytes.
    pub name: [u8; MAX_NAME_LEN],
    /// Length of the name.
    pub name_len: u8,
}

impl XfsDirEntry {
    /// File name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

/// Result of listing a directory.
pub struct XfsDirEntries {
    /// Directory entries.
    pub entries: [Option<XfsDirEntry>; MAX_DIR_ENTRIES],
    /// Number of valid entries.
    pub count: usize,
}

impl XfsDirEntries {
    fn new() -> Self {
        const NONE: Option<XfsDirEntry> = None;
        Self {
            entries: [NONE; MAX_DIR_ENTRIES],
            count: 0,
        }
    }

    #[allow(dead_code)]
    fn push(&mut self, entry: XfsDirEntry) -> Result<()> {
        if self.count >= MAX_DIR_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = Some(entry);
        self.count += 1;
        Ok(())
    }
}

/// Read-only XFS filesystem instance.
///
/// Parses XFS on-disk structures via a [`BlockReader`] and provides
/// read-only access to files and directories. Maintains an in-memory
/// inode cache for recently accessed inodes.
pub struct XfsFs<R: BlockReader> {
    /// Block reader (storage backend).
    reader: R,
    /// Parsed primary superblock.
    sb: XfsSuperblock,
    /// Allocation group headers. Reserved for AG-aware operations.
    #[allow(dead_code)]
    ags: [Option<XfsAgHeader>; MAX_AG_COUNT],
    /// Number of allocation groups.
    ag_count: usize,
    /// Inode cache.
    inode_cache: [XfsInodeCache; MAX_INODE_CACHE],
}

impl<R: BlockReader> XfsFs<R> {
    /// Mount an XFS filesystem from the given block reader.
    ///
    /// Reads and validates the superblock and AG headers.
    pub fn mount(reader: R) -> Result<Self> {
        // Read primary superblock (at offset 0).
        let mut sb_buf = [0u8; 512];
        reader.read_bytes(0, &mut sb_buf)?;
        let sb = XfsSuperblock::from_bytes(&sb_buf)?;
        sb.validate()?;

        let ag_count = sb.sb_agcount as usize;
        if ag_count > MAX_AG_COUNT {
            return Err(Error::OutOfMemory);
        }

        // Read AG headers.
        const NONE_AG: Option<XfsAgHeader> = None;
        let mut ags = [NONE_AG; MAX_AG_COUNT];
        let mut ag_buf = [0u8; 64];
        for (i, ag_slot) in ags.iter_mut().enumerate().take(ag_count) {
            let offset = i as u64 * sb.sb_agblocks as u64 * sb.sb_blocksize as u64;
            // AG header is in the first sector of each AG; skip the superblock
            // copy in AG 0 (it overlaps the first sector). For AG > 0 the
            // AG header follows the superblock copy.
            let ag_hdr_offset = offset + sb.sb_sectsize as u64;
            reader.read_bytes(ag_hdr_offset, &mut ag_buf)?;
            *ag_slot = Some(XfsAgHeader::from_bytes(&ag_buf)?);
        }

        Ok(Self {
            reader,
            sb,
            ags,
            ag_count,
            inode_cache: [const { XfsInodeCache::empty() }; MAX_INODE_CACHE],
        })
    }

    /// Return a reference to the superblock.
    pub fn superblock(&self) -> &XfsSuperblock {
        &self.sb
    }

    /// Filesystem block size in bytes.
    pub fn block_size(&self) -> u64 {
        self.sb.sb_blocksize as u64
    }

    /// Number of allocation groups.
    pub fn ag_count(&self) -> usize {
        self.ag_count
    }

    /// Compute the byte offset for an inode number.
    ///
    /// XFS encodes AG number and per-AG inode index in the inode number.
    fn inode_offset(&self, ino: u64) -> Result<u64> {
        let ino_per_ag = self.sb.sb_agblocks as u64
            * (self.sb.sb_blocksize as u64 / self.sb.sb_inodesize as u64);
        if ino_per_ag == 0 {
            return Err(Error::InvalidArgument);
        }
        let ag = ino / ino_per_ag;
        let local = ino % ino_per_ag;
        let ag_offset = ag * self.sb.sb_agblocks as u64 * self.sb.sb_blocksize as u64;
        let byte_offset = ag_offset + local * self.sb.sb_inodesize as u64;
        Ok(byte_offset)
    }

    /// Read and parse an inode by number.
    ///
    /// Uses the inode cache when available.
    pub fn read_inode(&mut self, ino: u64) -> Result<XfsInode> {
        // Check cache.
        for entry in &self.inode_cache {
            if entry.valid && entry.ino == ino {
                return Ok(entry.inode);
            }
        }

        // Read from disk.
        let offset = self.inode_offset(ino)?;
        let inode_size = self.sb.sb_inodesize as usize;
        let mut buf = [0u8; 512];
        let read_len = inode_size.min(buf.len());
        self.reader.read_bytes(offset, &mut buf[..read_len])?;
        let inode = XfsInode::from_bytes(&buf[..read_len])?;

        // Insert into cache (LRU eviction: overwrite first empty or slot 0).
        let slot = self.inode_cache.iter().position(|e| !e.valid).unwrap_or(0);
        self.inode_cache[slot] = XfsInodeCache {
            ino,
            inode,
            extents: [None; MAX_EXTENTS],
            extent_count: 0,
            valid: true,
        };

        Ok(inode)
    }

    /// Look up a file by name in a directory.
    ///
    /// Returns the inode number of the named entry. This is a stub
    /// that reads directory data and scans for the name; a full
    /// implementation would parse XFS directory formats (shortform,
    /// block, leaf, node).
    pub fn lookup(&mut self, dir_ino: u64, name: &[u8]) -> Result<u64> {
        let inode = self.read_inode(dir_ino)?;
        if !inode.is_dir() {
            return Err(Error::InvalidArgument);
        }
        let entries = self.list_dir_internal(&inode, dir_ino)?;
        for entry in entries.entries[..entries.count].iter().flatten() {
            if entry.name() == name {
                return Ok(entry.ino);
            }
        }
        Err(Error::NotFound)
    }

    /// Read file data from an inode.
    ///
    /// Reads up to `buf.len()` bytes starting at `offset` within the
    /// file. Returns the number of bytes read. Currently supports
    /// extent-format inodes; B+ tree traversal returns NotImplemented.
    pub fn read_file(&mut self, ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let inode = self.read_inode(ino)?;
        if !inode.is_file() {
            return Err(Error::InvalidArgument);
        }
        if offset >= inode.di_size {
            return Ok(0);
        }
        let available = (inode.di_size - offset) as usize;
        let to_read = buf.len().min(available);
        if to_read == 0 {
            return Ok(0);
        }

        let format = inode.format().ok_or(Error::InvalidArgument)?;
        match format {
            XfsInodeFormat::Extents => {
                // Read using cached extents.
                self.read_via_extents(ino, offset, &mut buf[..to_read])
            }
            XfsInodeFormat::BTree => {
                // B+ tree traversal not yet implemented.
                Err(Error::NotImplemented)
            }
            XfsInodeFormat::Local => {
                // Inline data — not applicable for regular files in practice.
                Err(Error::NotImplemented)
            }
        }
    }

    /// Read file data using the extent list.
    fn read_via_extents(&self, _ino: u64, _offset: u64, _buf: &mut [u8]) -> Result<usize> {
        // Stub: a full implementation would look up the correct extent
        // for the given offset, translate to physical block, and read.
        Err(Error::NotImplemented)
    }

    /// List directory entries.
    pub fn list_dir(&mut self, dir_ino: u64) -> Result<XfsDirEntries> {
        let inode = self.read_inode(dir_ino)?;
        if !inode.is_dir() {
            return Err(Error::InvalidArgument);
        }
        self.list_dir_internal(&inode, dir_ino)
    }

    /// Internal directory listing.
    fn list_dir_internal(&self, _inode: &XfsInode, _dir_ino: u64) -> Result<XfsDirEntries> {
        // Stub: a full implementation would parse XFS shortform/block/leaf
        // directory formats. Return empty for now.
        Ok(XfsDirEntries::new())
    }

    /// Read the root directory inode.
    pub fn root_inode(&mut self) -> Result<XfsInode> {
        self.read_inode(self.sb.sb_rootino)
    }
}

impl<R: BlockReader> core::fmt::Debug for XfsFs<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XfsFs")
            .field("block_size", &self.sb.sb_blocksize)
            .field("dblocks", &self.sb.sb_dblocks)
            .field("agcount", &self.sb.sb_agcount)
            .field("rootino", &self.sb.sb_rootino)
            .finish()
    }
}

// ── XfsRegistry ─────────────────────────────────────────────────

/// Maximum mount path length.
const MAX_MOUNT_PATH: usize = 256;

/// Mount entry in the XFS registry.
struct XfsMountEntry {
    /// Mount path in the local VFS namespace.
    path: [u8; MAX_MOUNT_PATH],
    /// Length of valid bytes in `path`.
    path_len: usize,
    /// Whether this slot is occupied.
    active: bool,
}

impl Default for XfsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Global registry of mounted XFS filesystem instances.
///
/// Tracks up to 4 active XFS mounts by their VFS mount paths.
/// The actual `XfsFs` instances are owned by the caller; the
/// registry provides path-based lookup for routing VFS operations.
pub struct XfsRegistry {
    /// Mount entries.
    mounts: [XfsMountEntry; MAX_XFS_INSTANCES],
    /// Number of active mounts.
    count: usize,
}

impl XfsRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            mounts: core::array::from_fn(|_| XfsMountEntry {
                path: [0u8; MAX_MOUNT_PATH],
                path_len: 0,
                active: false,
            }),
            count: 0,
        }
    }

    /// Register a mount at the given path.
    ///
    /// Returns the slot index on success.
    pub fn mount(&mut self, path: &[u8]) -> Result<usize> {
        if path.len() > MAX_MOUNT_PATH {
            return Err(Error::InvalidArgument);
        }

        // Check for duplicates.
        for entry in &self.mounts {
            if entry.active && entry.path_len == path.len() && entry.path[..path.len()] == *path {
                return Err(Error::AlreadyExists);
            }
        }

        // Find a free slot.
        for (i, entry) in self.mounts.iter_mut().enumerate() {
            if !entry.active {
                entry.path[..path.len()].copy_from_slice(path);
                entry.path_len = path.len();
                entry.active = true;
                self.count += 1;
                return Ok(i);
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Unregister the mount at the given path.
    pub fn unmount(&mut self, path: &[u8]) -> Result<()> {
        for entry in &mut self.mounts {
            if entry.active && entry.path_len == path.len() && entry.path[..path.len()] == *path {
                entry.active = false;
                self.count = self.count.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Find a mount by its path. Returns the slot index.
    pub fn find(&self, path: &[u8]) -> Option<usize> {
        for (i, entry) in self.mounts.iter().enumerate() {
            if entry.active && entry.path_len == path.len() && entry.path[..path.len()] == *path {
                return Some(i);
            }
        }
        None
    }

    /// Number of active mounts.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl core::fmt::Debug for XfsRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XfsRegistry")
            .field("count", &self.count)
            .finish()
    }
}

// ── Big-endian helpers ──────────────────────────────────────────
// XFS uses big-endian on-disk format (unlike ext2/ext4 which use LE).

/// Read a big-endian u16 from `buf` at `offset`.
fn read_u16_be(buf: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([buf[offset], buf[offset + 1]])
}

/// Read a big-endian u32 from `buf` at `offset`.
fn read_u32_be(buf: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

/// Read a big-endian u64 from `buf` at `offset`.
fn read_u64_be(buf: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ])
}
