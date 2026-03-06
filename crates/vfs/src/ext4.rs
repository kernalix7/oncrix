// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Read-only ext4 filesystem driver.
//!
//! Parses ext4 on-disk structures and provides read-only access to
//! files and directories. Supports:
//! - Superblock parsing with 64-bit block counts and feature flags
//! - Block group descriptor table (32-byte descriptors)
//! - Inode reading with extent tree support
//! - Directory entry iteration (ext4 `dir_entry2` format)
//! - File data reading via extent mapping
//!
//! The driver operates on the [`BlockReader`](crate::ext2::BlockReader)
//! trait, allowing it to work with any underlying storage backend.
//!
//! # ext4 vs ext2
//!
//! ext4 extends ext2/ext3 with:
//! - **Extents** instead of indirect block maps (inline 60-byte tree)
//! - **64-bit block addresses** via `s_blocks_count_hi`
//! - **Feature flags** (compat / incompat / ro_compat)
//! - **Larger block group descriptors** (64 bytes when 64-bit feature)
//!
//! # References
//!
//! - Linux `fs/ext4/` source tree
//! - <https://ext4.wiki.kernel.org/index.php/Ext4_Disk_Layout>

use crate::ext2::BlockReader;
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// ext4 on-disk constants
// ---------------------------------------------------------------------------

/// ext4 superblock magic (same as ext2/ext3).
const EXT4_MAGIC: u16 = 0xEF53;

/// Base block size (1024 << s_log_block_size).
const BASE_BLOCK_SIZE: u64 = 1024;

/// Superblock is always at byte offset 1024.
const SUPERBLOCK_OFFSET: u64 = 1024;

/// Maximum block size we support (64 KiB).
const MAX_BLOCK_SIZE: u64 = 65536;

/// Root directory inode number (always 2).
pub const EXT4_ROOT_INO: u32 = 2;

/// Maximum file name length.
const EXT4_NAME_LEN: usize = 255;

/// Maximum directory entries returned from a single readdir.
const MAX_DIR_ENTRIES: usize = 128;

/// Maximum block groups we support.
const MAX_BLOCK_GROUPS: usize = 128;

/// Maximum inode cache entries.
const MAX_INODE_CACHE: usize = 256;

/// Maximum depth of an extent tree.
const EXT4_MAX_EXTENT_DEPTH: u16 = 5;

/// Extent header magic.
const EXT4_EXT_MAGIC: u16 = 0xF30A;

// ---------------------------------------------------------------------------
// Inode type bits (from i_mode)
// ---------------------------------------------------------------------------

/// Inode type mask (upper 4 bits of i_mode).
const S_IFMT: u16 = 0xF000;
/// Regular file.
const S_IFREG: u16 = 0x8000;
/// Directory.
const S_IFDIR: u16 = 0x4000;
/// Symbolic link.
const S_IFLNK: u16 = 0xA000;
/// Character device.
const S_IFCHR: u16 = 0x2000;
/// Block device.
const S_IFBLK: u16 = 0x6000;

// ---------------------------------------------------------------------------
// Feature flags
// ---------------------------------------------------------------------------

/// Compatible feature: directory preallocation.
pub const EXT4_FEATURE_COMPAT_DIR_PREALLOC: u32 = 0x0001;
/// Compatible feature: has journal (ext3-style).
pub const EXT4_FEATURE_COMPAT_HAS_JOURNAL: u32 = 0x0004;
/// Compatible feature: extended attributes.
pub const EXT4_FEATURE_COMPAT_EXT_ATTR: u32 = 0x0008;

/// Incompatible feature: uses extents.
pub const EXT4_FEATURE_INCOMPAT_EXTENTS: u32 = 0x0040;
/// Incompatible feature: 64-bit block numbers.
pub const EXT4_FEATURE_INCOMPAT_64BIT: u32 = 0x0002;
/// Incompatible feature: flexible block groups.
pub const EXT4_FEATURE_INCOMPAT_FLEX_BG: u32 = 0x0200;

/// Read-only compatible feature: sparse superblock.
pub const EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER: u32 = 0x0001;
/// Read-only compatible feature: large file.
pub const EXT4_FEATURE_RO_COMPAT_LARGE_FILE: u32 = 0x0002;
/// Read-only compatible feature: huge file.
pub const EXT4_FEATURE_RO_COMPAT_HUGE_FILE: u32 = 0x0008;

// ---------------------------------------------------------------------------
// On-disk structures
// ---------------------------------------------------------------------------

/// ext4 superblock.
///
/// Extends the ext2 superblock with 64-bit block counts, feature
/// flags, and additional metadata fields.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Ext4Superblock {
    /// Total number of inodes.
    pub s_inodes_count: u32,
    /// Total block count (low 32 bits).
    pub s_blocks_count_lo: u32,
    /// Number of free blocks (low 32 bits).
    pub s_free_blocks_count_lo: u32,
    /// Number of free inodes.
    pub s_free_inodes_count: u32,
    /// Block size = 1024 << s_log_block_size.
    pub s_log_block_size: u32,
    /// Blocks per group.
    pub s_blocks_per_group: u32,
    /// Inodes per group.
    pub s_inodes_per_group: u32,
    /// Magic number (must be 0xEF53).
    pub s_magic: u16,
    /// Inode size in bytes.
    pub s_inode_size: u16,
    /// Compatible feature set.
    pub s_feature_compat: u32,
    /// Incompatible feature set.
    pub s_feature_incompat: u32,
    /// Read-only compatible feature set.
    pub s_feature_ro_compat: u32,
    /// Total block count (high 32 bits, if 64-bit feature).
    pub s_blocks_count_hi: u32,
    /// Free blocks count (high 32 bits, if 64-bit feature).
    pub s_free_blocks_count_hi: u32,
    /// First data block (0 for >=4K blocks, 1 for 1K).
    pub s_first_data_block: u32,
    /// Filesystem revision level.
    pub s_rev_level: u32,
}

impl Ext4Superblock {
    /// Parse an ext4 superblock from a 1024-byte buffer.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 1024 {
            return Err(Error::InvalidArgument);
        }
        let magic = read_u16(buf, 56);
        if magic != EXT4_MAGIC {
            return Err(Error::InvalidArgument);
        }
        let rev_level = read_u32(buf, 76);
        let inode_size = if rev_level >= 1 {
            read_u16(buf, 88)
        } else {
            128
        };

        Ok(Self {
            s_inodes_count: read_u32(buf, 0),
            s_blocks_count_lo: read_u32(buf, 4),
            s_free_blocks_count_lo: read_u32(buf, 12),
            s_free_inodes_count: read_u32(buf, 16),
            s_log_block_size: read_u32(buf, 24),
            s_blocks_per_group: read_u32(buf, 32),
            s_inodes_per_group: read_u32(buf, 40),
            s_magic: magic,
            s_inode_size: inode_size,
            s_feature_compat: read_u32(buf, 92),
            s_feature_incompat: read_u32(buf, 96),
            s_feature_ro_compat: read_u32(buf, 100),
            // 64-bit fields at superblock offsets 0x150 (336) and 0x158 (344).
            s_blocks_count_hi: read_u32(buf, 336),
            s_free_blocks_count_hi: read_u32(buf, 340),
            s_first_data_block: read_u32(buf, 20),
            s_rev_level: rev_level,
        })
    }

    /// Computed block size in bytes.
    pub fn block_size(&self) -> u64 {
        BASE_BLOCK_SIZE << self.s_log_block_size
    }

    /// Total block count (64-bit).
    pub fn blocks_count(&self) -> u64 {
        let lo = self.s_blocks_count_lo as u64;
        let hi = self.s_blocks_count_hi as u64;
        lo | (hi << 32)
    }

    /// Free block count (64-bit).
    pub fn free_blocks_count(&self) -> u64 {
        let lo = self.s_free_blocks_count_lo as u64;
        let hi = self.s_free_blocks_count_hi as u64;
        lo | (hi << 32)
    }

    /// Number of block groups.
    pub fn block_group_count(&self) -> u32 {
        if self.s_blocks_per_group == 0 {
            return 0;
        }
        self.s_blocks_count_lo.div_ceil(self.s_blocks_per_group)
    }

    /// Whether the 64-bit feature is enabled.
    pub fn has_64bit(&self) -> bool {
        self.s_feature_incompat & EXT4_FEATURE_INCOMPAT_64BIT != 0
    }

    /// Whether the filesystem uses extents.
    pub fn has_extents(&self) -> bool {
        self.s_feature_incompat & EXT4_FEATURE_INCOMPAT_EXTENTS != 0
    }
}

// ---------------------------------------------------------------------------
// Block group descriptor
// ---------------------------------------------------------------------------

/// ext4 block group descriptor (32 bytes; 64 bytes with 64-bit feature).
///
/// We parse the common 32-byte portion used by both 32-bit and 64-bit
/// format variants.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Ext4BlockGroupDesc {
    /// Block bitmap block number.
    pub bg_block_bitmap: u32,
    /// Inode bitmap block number.
    pub bg_inode_bitmap: u32,
    /// First inode table block number.
    pub bg_inode_table: u32,
    /// Number of free blocks in this group.
    pub bg_free_blocks_count: u16,
    /// Number of free inodes in this group.
    pub bg_free_inodes_count: u16,
    /// Number of directories in this group.
    pub bg_used_dirs_count: u16,
}

impl Ext4BlockGroupDesc {
    /// Parse a block group descriptor from a buffer (at least 32 bytes).
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 32 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            bg_block_bitmap: read_u32(buf, 0),
            bg_inode_bitmap: read_u32(buf, 4),
            bg_inode_table: read_u32(buf, 8),
            bg_free_blocks_count: read_u16(buf, 12),
            bg_free_inodes_count: read_u16(buf, 14),
            bg_used_dirs_count: read_u16(buf, 16),
        })
    }
}

// ---------------------------------------------------------------------------
// ext4 inode (with extent support)
// ---------------------------------------------------------------------------

/// ext4 inode with inline extent tree data.
///
/// The 60 bytes at offset 40 in the on-disk inode can hold either
/// classic block pointers (ext2-style) or an inline extent tree.
/// When the inode's `EXT4_EXTENTS_FL` flag is set, the 60 bytes
/// contain an extent header followed by extent entries.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Ext4Inode {
    /// File mode (type + permissions).
    pub i_mode: u16,
    /// Owner UID.
    pub i_uid: u16,
    /// File size (lower 32 bits).
    pub i_size_lo: u32,
    /// Last access time.
    pub i_atime: u32,
    /// Inode change time.
    pub i_ctime: u32,
    /// Last modification time.
    pub i_mtime: u32,
    /// Number of 512-byte sectors.
    pub i_blocks_lo: u32,
    /// Inode flags.
    pub i_flags: u32,
    /// File size (upper 32 bits).
    pub i_size_hi: u32,
    /// Inline extent tree data (60 bytes).
    pub i_extent_data: [u8; 60],
}

/// Inode flag: uses extents (not indirect blocks).
pub const EXT4_EXTENTS_FL: u32 = 0x0008_0000;

impl Ext4Inode {
    /// Parse an ext4 inode from a buffer (at least 128 bytes).
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 128 {
            return Err(Error::InvalidArgument);
        }
        let mut extent_data = [0u8; 60];
        extent_data.copy_from_slice(&buf[40..100]);

        Ok(Self {
            i_mode: read_u16(buf, 0),
            i_uid: read_u16(buf, 2),
            i_size_lo: read_u32(buf, 4),
            i_atime: read_u32(buf, 8),
            i_ctime: read_u32(buf, 12),
            i_mtime: read_u32(buf, 16),
            i_blocks_lo: read_u32(buf, 28),
            i_flags: read_u32(buf, 32),
            i_size_hi: if buf.len() >= 112 {
                read_u32(buf, 108)
            } else {
                0
            },
            i_extent_data: extent_data,
        })
    }

    /// Full file size in bytes (64-bit).
    pub fn size(&self) -> u64 {
        let lo = self.i_size_lo as u64;
        let hi = self.i_size_hi as u64;
        lo | (hi << 32)
    }

    /// File type from i_mode.
    pub fn file_type(&self) -> Option<crate::inode::FileType> {
        match self.i_mode & S_IFMT {
            S_IFREG => Some(crate::inode::FileType::Regular),
            S_IFDIR => Some(crate::inode::FileType::Directory),
            S_IFLNK => Some(crate::inode::FileType::Symlink),
            S_IFCHR => Some(crate::inode::FileType::CharDevice),
            S_IFBLK => Some(crate::inode::FileType::BlockDevice),
            _ => None,
        }
    }

    /// POSIX permission bits (lower 12 bits of i_mode).
    pub fn permissions(&self) -> u16 {
        self.i_mode & 0x0FFF
    }

    /// Whether this inode uses the extent tree format.
    pub fn uses_extents(&self) -> bool {
        self.i_flags & EXT4_EXTENTS_FL != 0
    }
}

// ---------------------------------------------------------------------------
// Extent tree structures
// ---------------------------------------------------------------------------

/// ext4 extent header (12 bytes).
///
/// Present at the start of each extent tree node (including the
/// inline 60 bytes in the inode).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Ext4ExtentHeader {
    /// Magic number (0xF30A).
    pub eh_magic: u16,
    /// Number of valid entries following this header.
    pub eh_entries: u16,
    /// Maximum number of entries that could follow.
    pub eh_max: u16,
    /// Depth of this node (0 = leaf, >0 = internal).
    pub eh_depth: u16,
    /// Generation (unused by us).
    pub eh_generation: u32,
}

impl Ext4ExtentHeader {
    /// Parse an extent header from a buffer (at least 12 bytes).
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 12 {
            return Err(Error::InvalidArgument);
        }
        let hdr = Self {
            eh_magic: read_u16(buf, 0),
            eh_entries: read_u16(buf, 2),
            eh_max: read_u16(buf, 4),
            eh_depth: read_u16(buf, 6),
            eh_generation: read_u32(buf, 8),
        };
        if hdr.eh_magic != EXT4_EXT_MAGIC {
            return Err(Error::InvalidArgument);
        }
        Ok(hdr)
    }
}

/// ext4 extent (leaf node entry, 12 bytes).
///
/// Maps a contiguous range of logical blocks to physical blocks.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Ext4Extent {
    /// First logical block this extent covers.
    pub ee_block: u32,
    /// Number of blocks covered (max 32768; bit 15 = uninitialized).
    pub ee_len: u16,
    /// Physical block number (high 16 bits).
    pub ee_start_hi: u16,
    /// Physical block number (low 32 bits).
    pub ee_start_lo: u32,
}

impl Ext4Extent {
    /// Parse an extent from a buffer (at least 12 bytes).
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 12 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            ee_block: read_u32(buf, 0),
            ee_len: read_u16(buf, 4),
            ee_start_hi: read_u16(buf, 6),
            ee_start_lo: read_u32(buf, 8),
        })
    }

    /// Physical start block (48-bit).
    pub fn start_block(&self) -> u64 {
        let lo = self.ee_start_lo as u64;
        let hi = self.ee_start_hi as u64;
        lo | (hi << 32)
    }

    /// Number of blocks in this extent (masking out the uninitialized bit).
    pub fn block_count(&self) -> u32 {
        (self.ee_len & 0x7FFF) as u32
    }

    /// Whether this extent is uninitialized (pre-allocated but not written).
    pub fn is_uninitialized(&self) -> bool {
        self.ee_len & 0x8000 != 0
    }
}

/// ext4 extent index (internal node entry, 12 bytes).
///
/// Points to a child extent tree node on disk.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Ext4ExtentIdx {
    /// First logical block this index covers.
    pub ei_block: u32,
    /// Physical block of the child node (low 32 bits).
    pub ei_leaf_lo: u32,
    /// Physical block of the child node (high 16 bits).
    pub ei_leaf_hi: u16,
    /// Padding.
    pub ei_unused: u16,
}

impl Ext4ExtentIdx {
    /// Parse an extent index from a buffer (at least 12 bytes).
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 12 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            ei_block: read_u32(buf, 0),
            ei_leaf_lo: read_u32(buf, 4),
            ei_leaf_hi: read_u16(buf, 8),
            ei_unused: read_u16(buf, 10),
        })
    }

    /// Physical block of the child node (48-bit).
    pub fn leaf_block(&self) -> u64 {
        let lo = self.ei_leaf_lo as u64;
        let hi = self.ei_leaf_hi as u64;
        lo | (hi << 32)
    }
}

// ---------------------------------------------------------------------------
// Directory entry
// ---------------------------------------------------------------------------

/// ext4 directory entry (variable length, 8-byte header + name).
///
/// Uses the `dir_entry2` format with an explicit `file_type` byte.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct Ext4DirEntry2 {
    /// Inode number for this entry.
    pub inode: u32,
    /// Total record length (for alignment/padding).
    pub rec_len: u16,
    /// Name length.
    pub name_len: u8,
    /// File type indicator.
    pub file_type: u8,
    /// File name (up to 255 bytes).
    pub name: [u8; EXT4_NAME_LEN],
}

impl Ext4DirEntry2 {
    /// File name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

/// Result of reading a directory.
pub struct Ext4DirEntries {
    /// Directory entries.
    pub entries: [Option<Ext4DirEntry2>; MAX_DIR_ENTRIES],
    /// Number of valid entries.
    pub count: usize,
}

impl Ext4DirEntries {
    fn new() -> Self {
        const NONE: Option<Ext4DirEntry2> = None;
        Self {
            entries: [NONE; MAX_DIR_ENTRIES],
            count: 0,
        }
    }

    fn push(&mut self, entry: Ext4DirEntry2) -> Result<()> {
        if self.count >= MAX_DIR_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = Some(entry);
        self.count += 1;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Inode cache entry
// ---------------------------------------------------------------------------

/// Cached inode entry for quick re-lookup.
#[derive(Clone, Copy)]
struct InodeCacheEntry {
    /// Inode number (0 = unused slot).
    ino: u32,
    /// Cached inode data.
    inode: Ext4Inode,
}

impl InodeCacheEntry {
    const fn empty() -> Self {
        Self {
            ino: 0,
            inode: Ext4Inode {
                i_mode: 0,
                i_uid: 0,
                i_size_lo: 0,
                i_atime: 0,
                i_ctime: 0,
                i_mtime: 0,
                i_blocks_lo: 0,
                i_flags: 0,
                i_size_hi: 0,
                i_extent_data: [0u8; 60],
            },
        }
    }
}

// ---------------------------------------------------------------------------
// ext4 filesystem driver
// ---------------------------------------------------------------------------

/// Read-only ext4 filesystem.
///
/// Operates over a [`BlockReader`](crate::ext2::BlockReader) to access
/// the underlying block device. All operations are read-only.
pub struct Ext4Fs<R: BlockReader> {
    /// Block reader (storage backend).
    reader: R,
    /// Parsed superblock.
    sb: Ext4Superblock,
    /// Block group descriptors.
    bgd: [Option<Ext4BlockGroupDesc>; MAX_BLOCK_GROUPS],
    /// Number of block groups.
    bg_count: usize,
    /// Inode cache (simple direct-mapped).
    inode_cache: [InodeCacheEntry; MAX_INODE_CACHE],
}

impl<R: BlockReader> Ext4Fs<R> {
    /// Mount an ext4 filesystem from the given block reader.
    ///
    /// Reads and validates the superblock and block group descriptor table.
    pub fn mount(reader: R) -> Result<Self> {
        let mut sb_buf = [0u8; 1024];
        reader.read_bytes(SUPERBLOCK_OFFSET, &mut sb_buf)?;
        let sb = Ext4Superblock::from_bytes(&sb_buf)?;

        let block_size = sb.block_size();
        if block_size > MAX_BLOCK_SIZE {
            return Err(Error::InvalidArgument);
        }

        let bg_count = sb.block_group_count() as usize;
        if bg_count > MAX_BLOCK_GROUPS {
            return Err(Error::OutOfMemory);
        }

        // BGD table starts at the block after the superblock.
        let bgd_block = if block_size == 1024 { 2 } else { 1 };
        let bgd_offset = bgd_block * block_size;

        const NONE_BGD: Option<Ext4BlockGroupDesc> = None;
        let mut bgd = [NONE_BGD; MAX_BLOCK_GROUPS];

        let mut bgd_buf = [0u8; 32];
        for (i, slot) in bgd.iter_mut().enumerate().take(bg_count) {
            let offset = bgd_offset + (i as u64 * 32);
            reader.read_bytes(offset, &mut bgd_buf)?;
            *slot = Some(Ext4BlockGroupDesc::from_bytes(&bgd_buf)?);
        }

        Ok(Self {
            reader,
            sb,
            bgd,
            bg_count,
            inode_cache: [InodeCacheEntry::empty(); MAX_INODE_CACHE],
        })
    }

    /// Return the parsed superblock.
    pub fn superblock(&self) -> &Ext4Superblock {
        &self.sb
    }

    /// Block size in bytes.
    pub fn block_size(&self) -> u64 {
        self.sb.block_size()
    }

    /// Read a raw block into `buf`.
    ///
    /// `buf` must be at least `block_size()` bytes.
    pub fn read_block(&self, block_num: u64, buf: &mut [u8]) -> Result<()> {
        let offset = block_num * self.block_size();
        let len = self.block_size() as usize;
        if buf.len() < len {
            return Err(Error::InvalidArgument);
        }
        self.reader.read_bytes(offset, &mut buf[..len])
    }

    /// Read an inode by number.
    pub fn read_inode(&mut self, ino: u32) -> Result<Ext4Inode> {
        if ino == 0 {
            return Err(Error::InvalidArgument);
        }

        // Check cache first.
        let cache_idx = (ino as usize) % MAX_INODE_CACHE;
        if self.inode_cache[cache_idx].ino == ino {
            return Ok(self.inode_cache[cache_idx].inode);
        }

        // Inode numbers are 1-based.
        let idx = ino - 1;
        let group = (idx / self.sb.s_inodes_per_group) as usize;
        let local_idx = idx % self.sb.s_inodes_per_group;

        if group >= self.bg_count {
            return Err(Error::NotFound);
        }
        let bgd = self.bgd[group].as_ref().ok_or(Error::NotFound)?;

        let inode_size = self.sb.s_inode_size as u64;
        let offset = bgd.bg_inode_table as u64 * self.block_size() + local_idx as u64 * inode_size;

        let mut buf = [0u8; 256];
        let read_len = (inode_size as usize).min(buf.len());
        self.reader.read_bytes(offset, &mut buf[..read_len])?;
        let inode = Ext4Inode::from_bytes(&buf[..read_len])?;

        // Store in cache.
        self.inode_cache[cache_idx] = InodeCacheEntry { ino, inode };

        Ok(inode)
    }

    /// Read the root directory inode.
    pub fn root_inode(&mut self) -> Result<Ext4Inode> {
        self.read_inode(EXT4_ROOT_INO)
    }

    /// Map a logical file block to a physical disk block using the extent tree.
    ///
    /// Returns the physical block number, or `None` for a hole.
    fn extent_map_block(&self, inode: &Ext4Inode, logical_block: u32) -> Result<Option<u64>> {
        // Parse the inline extent header from the inode's 60-byte data area.
        let hdr = Ext4ExtentHeader::from_bytes(&inode.i_extent_data)?;

        if hdr.eh_depth > EXT4_MAX_EXTENT_DEPTH {
            return Err(Error::InvalidArgument);
        }

        if hdr.eh_depth == 0 {
            // Leaf node — search extents directly in the inode data.
            return self.search_leaf_extents(
                &inode.i_extent_data[12..],
                hdr.eh_entries,
                logical_block,
            );
        }

        // Internal node — walk down the tree.
        self.walk_extent_tree(&inode.i_extent_data, hdr.eh_depth, logical_block)
    }

    /// Search leaf extent entries for the given logical block.
    fn search_leaf_extents(
        &self,
        data: &[u8],
        entries: u16,
        logical_block: u32,
    ) -> Result<Option<u64>> {
        for i in 0..entries as usize {
            let off = i * 12;
            if off + 12 > data.len() {
                break;
            }
            let ext = Ext4Extent::from_bytes(&data[off..])?;
            let ext_end = ext.ee_block.saturating_add(ext.block_count());
            if logical_block >= ext.ee_block && logical_block < ext_end {
                if ext.is_uninitialized() {
                    return Ok(None); // pre-allocated hole
                }
                let offset_in_extent = (logical_block - ext.ee_block) as u64;
                return Ok(Some(ext.start_block() + offset_in_extent));
            }
        }
        Ok(None) // hole
    }

    /// Walk the extent tree from an internal node down to the leaf.
    fn walk_extent_tree(
        &self,
        node_data: &[u8],
        depth: u16,
        logical_block: u32,
    ) -> Result<Option<u64>> {
        let hdr = Ext4ExtentHeader::from_bytes(node_data)?;
        let entries = hdr.eh_entries as usize;

        if hdr.eh_depth == 0 {
            // Leaf node.
            return self.search_leaf_extents(&node_data[12..], hdr.eh_entries, logical_block);
        }

        // Find the correct index entry (largest ei_block <= logical_block).
        let mut chosen: Option<Ext4ExtentIdx> = None;
        for i in 0..entries {
            let off = 12 + i * 12;
            if off + 12 > node_data.len() {
                break;
            }
            let idx = Ext4ExtentIdx::from_bytes(&node_data[off..])?;
            if idx.ei_block <= logical_block {
                chosen = Some(idx);
            } else {
                break;
            }
        }

        let idx = match chosen {
            Some(idx) => idx,
            None => return Ok(None), // hole before any extents
        };

        if depth > EXT4_MAX_EXTENT_DEPTH {
            return Err(Error::InvalidArgument);
        }

        // Read the child node block.
        let bs = self.block_size() as usize;
        // We use a fixed-size buffer; block sizes above 4096 are read
        // partially (the extent entries we need are always at the start).
        let mut child_buf = [0u8; 4096];
        let read_len = bs.min(child_buf.len());
        let child_offset = idx.leaf_block() * self.block_size();
        self.reader
            .read_bytes(child_offset, &mut child_buf[..read_len])?;

        self.walk_extent_tree(&child_buf[..read_len], depth - 1, logical_block)
    }

    /// Read file data from an inode.
    ///
    /// Reads up to `buf.len()` bytes starting at `offset` within the file.
    /// Returns the number of bytes actually read.
    pub fn read_file(&self, inode: &Ext4Inode, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let file_size = inode.size();
        if offset >= file_size {
            return Ok(0);
        }
        let available = (file_size - offset) as usize;
        let to_read = buf.len().min(available);
        if to_read == 0 {
            return Ok(0);
        }

        let bs = self.block_size();
        let mut bytes_read = 0usize;
        let mut file_offset = offset;

        while bytes_read < to_read {
            let file_block = (file_offset / bs) as u32;
            let block_offset = (file_offset % bs) as usize;
            let chunk = (bs as usize - block_offset).min(to_read - bytes_read);

            if inode.uses_extents() {
                match self.extent_map_block(inode, file_block)? {
                    Some(phys_block) => {
                        let disk_offset = phys_block * bs + block_offset as u64;
                        self.reader
                            .read_bytes(disk_offset, &mut buf[bytes_read..bytes_read + chunk])?;
                    }
                    None => {
                        // Hole — fill with zeros.
                        for b in &mut buf[bytes_read..bytes_read + chunk] {
                            *b = 0;
                        }
                    }
                }
            } else {
                // No extents — this inode uses legacy block pointers.
                // For simplicity, treat as hole (ext4 should always use extents).
                for b in &mut buf[bytes_read..bytes_read + chunk] {
                    *b = 0;
                }
            }

            bytes_read += chunk;
            file_offset += chunk as u64;
        }

        Ok(bytes_read)
    }

    /// Read all directory entries from a directory inode.
    pub fn read_dir(&self, inode: &Ext4Inode) -> Result<Ext4DirEntries> {
        if inode.file_type() != Some(crate::inode::FileType::Directory) {
            return Err(Error::InvalidArgument);
        }

        let mut result = Ext4DirEntries::new();
        let dir_size = inode.size();
        let mut offset = 0u64;

        while offset < dir_size {
            let mut hdr = [0u8; 8];
            let read = self.read_file(inode, offset, &mut hdr)?;
            if read < 8 {
                break;
            }

            let entry_inode = read_u32(&hdr, 0);
            let rec_len = read_u16(&hdr, 4) as u64;
            let name_len = hdr[6];
            let file_type_indicator = hdr[7];

            if rec_len == 0 {
                break;
            }

            if entry_inode != 0 && name_len > 0 {
                let mut entry = Ext4DirEntry2 {
                    inode: entry_inode,
                    rec_len: rec_len as u16,
                    name_len,
                    file_type: file_type_indicator,
                    name: [0u8; EXT4_NAME_LEN],
                };

                let nl = name_len as usize;
                if nl <= EXT4_NAME_LEN {
                    self.read_file(inode, offset + 8, &mut entry.name[..nl])?;
                }

                let _ = result.push(entry);
            }

            offset += rec_len;
        }

        Ok(result)
    }

    /// Look up a file by name in a directory inode.
    ///
    /// Returns the inode number if found.
    pub fn lookup(&self, dir_inode: &Ext4Inode, name: &[u8]) -> Result<u32> {
        let entries = self.read_dir(dir_inode)?;
        for entry in entries.entries[..entries.count].iter().flatten() {
            if entry.name() == name {
                return Ok(entry.inode);
            }
        }
        Err(Error::NotFound)
    }

    /// Resolve a path from the root to an inode.
    ///
    /// Path components are separated by `/`. Leading `/` is optional.
    pub fn resolve_path(&mut self, path: &[u8]) -> Result<Ext4Inode> {
        let mut current = self.read_inode(EXT4_ROOT_INO)?;

        for component in Ext4PathComponents::new(path) {
            if component.is_empty() {
                continue;
            }
            let ino = self.lookup(&current, component)?;
            current = self.read_inode(ino)?;
        }

        Ok(current)
    }

    /// List all entries in a directory identified by path.
    pub fn list_dir(&mut self, path: &[u8]) -> Result<Ext4DirEntries> {
        let inode = self.resolve_path(path)?;
        self.read_dir(&inode)
    }
}

impl<R: BlockReader> core::fmt::Debug for Ext4Fs<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ext4Fs")
            .field("block_size", &self.block_size())
            .field("blocks", &self.sb.blocks_count())
            .field("inodes", &self.sb.s_inodes_count)
            .field("block_groups", &self.bg_count)
            .field("has_extents", &self.sb.has_extents())
            .field("has_64bit", &self.sb.has_64bit())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Path component iterator
// ---------------------------------------------------------------------------

/// Simple path component iterator (splits on `/`).
struct Ext4PathComponents<'a> {
    remaining: &'a [u8],
}

impl<'a> Ext4PathComponents<'a> {
    fn new(path: &'a [u8]) -> Self {
        Self { remaining: path }
    }
}

impl<'a> Iterator for Ext4PathComponents<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        while self.remaining.first() == Some(&b'/') {
            self.remaining = &self.remaining[1..];
        }
        if self.remaining.is_empty() {
            return None;
        }
        let end = self
            .remaining
            .iter()
            .position(|&b| b == b'/')
            .unwrap_or(self.remaining.len());
        let component = &self.remaining[..end];
        self.remaining = &self.remaining[end..];
        Some(component)
    }
}

// ---------------------------------------------------------------------------
// Ext4Registry — multiple mounted ext4 instances
// ---------------------------------------------------------------------------

/// Maximum number of concurrent ext4 mount points.
const MAX_EXT4_MOUNTS: usize = 4;

/// Registry for multiple mounted ext4 filesystem instances.
///
/// Allows the kernel to track up to [`MAX_EXT4_MOUNTS`] concurrently
/// mounted ext4 filesystems, identified by a mount index.
pub struct Ext4Registry {
    /// Mount point names (for identification).
    names: [Option<[u8; 64]>; MAX_EXT4_MOUNTS],
    /// Number of active mounts.
    count: usize,
}

impl Ext4Registry {
    /// Create a new, empty registry.
    pub const fn new() -> Self {
        const NONE_NAME: Option<[u8; 64]> = None;
        Self {
            names: [NONE_NAME; MAX_EXT4_MOUNTS],
            count: 0,
        }
    }

    /// Register a new mount point name. Returns the mount index.
    pub fn register(&mut self, name: &[u8]) -> Result<usize> {
        if self.count >= MAX_EXT4_MOUNTS {
            return Err(Error::OutOfMemory);
        }
        let slot = self
            .names
            .iter()
            .position(|n| n.is_none())
            .ok_or(Error::OutOfMemory)?;

        let mut buf = [0u8; 64];
        let len = name.len().min(64);
        buf[..len].copy_from_slice(&name[..len]);
        self.names[slot] = Some(buf);
        self.count += 1;
        Ok(slot)
    }

    /// Unregister a mount by index.
    pub fn unregister(&mut self, index: usize) -> Result<()> {
        if index >= MAX_EXT4_MOUNTS || self.names[index].is_none() {
            return Err(Error::NotFound);
        }
        self.names[index] = None;
        self.count -= 1;
        Ok(())
    }

    /// Number of active mounts.
    pub fn mount_count(&self) -> usize {
        self.count
    }

    /// Check if a mount index is active.
    pub fn is_mounted(&self, index: usize) -> bool {
        index < MAX_EXT4_MOUNTS && self.names[index].is_some()
    }
}

impl Default for Ext4Registry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Little-endian helpers
// ---------------------------------------------------------------------------

/// Read a little-endian u16 from `buf` at `offset`.
fn read_u16(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

/// Read a little-endian u32 from `buf` at `offset`.
fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}
