// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Read-only ext2 filesystem driver.
//!
//! Parses ext2 on-disk structures and provides read-only access to
//! files and directories. This is a minimal implementation supporting:
//! - Superblock parsing and validation
//! - Block group descriptor table
//! - Inode reading (direct + single-indirect blocks)
//! - Directory entry iteration
//! - File data reading
//!
//! The driver operates on a block-level `BlockReader` trait, allowing
//! it to work with any underlying storage (virtio-blk, ramdisk, etc.).
//!
//! Reference: `.kernelORG/` — `filesystems/ext2.rst`;
//! <https://www.nongnu.org/ext2-doc/ext2.html>

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// ext2 on-disk constants
// ---------------------------------------------------------------------------

/// ext2 superblock magic number.
const EXT2_MAGIC: u16 = 0xEF53;

/// Block size for the default case (1024 << 0 = 1024 bytes).
/// Actual block size = 1024 << `s_log_block_size`.
const BASE_BLOCK_SIZE: u64 = 1024;

/// Superblock is always at byte offset 1024.
const SUPERBLOCK_OFFSET: u64 = 1024;

/// Maximum block size we support (64 KiB).
const MAX_BLOCK_SIZE: u64 = 65536;

/// Root directory inode number (always 2 in ext2).
pub const EXT2_ROOT_INO: u32 = 2;

/// Maximum file name length in a directory entry.
const EXT2_NAME_LEN: usize = 255;

/// Number of direct block pointers in an inode.
const EXT2_NDIR_BLOCKS: usize = 12;

/// Index of indirect block pointer.
const EXT2_IND_BLOCK: usize = 12;

/// Maximum blocks we can address (direct + single indirect).
/// With 4K blocks: 12 + 1024 = 1036 blocks = ~4 MiB.
const MAX_ADDRESSABLE_BLOCKS: usize = EXT2_NDIR_BLOCKS + 1024;

/// Maximum directory entries we return from a single readdir.
const MAX_DIR_ENTRIES: usize = 128;

// ---------------------------------------------------------------------------
// ext2 inode type bits (from i_mode)
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
// Block reader trait
// ---------------------------------------------------------------------------

/// Trait for reading blocks from the underlying storage.
///
/// Implementations must read `block_size` bytes from the given
/// byte offset into `buf`.
pub trait BlockReader {
    /// Read `buf.len()` bytes starting at byte `offset`.
    fn read_bytes(&self, offset: u64, buf: &mut [u8]) -> Result<()>;
}

// ---------------------------------------------------------------------------
// On-disk structures
// ---------------------------------------------------------------------------

/// ext2 superblock (on-disk, 1024 bytes; we only parse the first ~100).
#[derive(Debug, Clone, Copy)]
pub struct Ext2Superblock {
    /// Total number of inodes.
    pub s_inodes_count: u32,
    /// Total number of blocks.
    pub s_blocks_count: u32,
    /// Number of free blocks.
    pub s_free_blocks_count: u32,
    /// Number of free inodes.
    pub s_free_inodes_count: u32,
    /// First data block (0 for >=4K blocks, 1 for 1K blocks).
    pub s_first_data_block: u32,
    /// Block size = 1024 << s_log_block_size.
    pub s_log_block_size: u32,
    /// Blocks per group.
    pub s_blocks_per_group: u32,
    /// Inodes per group.
    pub s_inodes_per_group: u32,
    /// Magic number (must be 0xEF53).
    pub s_magic: u16,
    /// Inode size in bytes (default 128 for rev 0).
    pub s_inode_size: u16,
    /// Filesystem revision level.
    pub s_rev_level: u32,
}

impl Ext2Superblock {
    /// Parse a superblock from a 1024-byte buffer.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 1024 {
            return Err(Error::InvalidArgument);
        }
        let sb = Self {
            s_inodes_count: read_u32(buf, 0),
            s_blocks_count: read_u32(buf, 4),
            s_free_blocks_count: read_u32(buf, 12),
            s_free_inodes_count: read_u32(buf, 16),
            s_first_data_block: read_u32(buf, 20),
            s_log_block_size: read_u32(buf, 24),
            s_blocks_per_group: read_u32(buf, 32),
            s_inodes_per_group: read_u32(buf, 40),
            s_magic: read_u16(buf, 56),
            s_inode_size: if read_u32(buf, 76) >= 1 {
                // rev >= 1: inode size at offset 88
                read_u16(buf, 88)
            } else {
                128
            },
            s_rev_level: read_u32(buf, 76),
        };
        if sb.s_magic != EXT2_MAGIC {
            return Err(Error::InvalidArgument);
        }
        Ok(sb)
    }

    /// Computed block size in bytes.
    pub fn block_size(&self) -> u64 {
        BASE_BLOCK_SIZE << self.s_log_block_size
    }

    /// Number of block groups.
    pub fn block_group_count(&self) -> u32 {
        self.s_blocks_count.div_ceil(self.s_blocks_per_group)
    }
}

/// Block group descriptor (32 bytes on disk).
#[derive(Debug, Clone, Copy)]
pub struct BlockGroupDesc {
    /// Block number of the block bitmap.
    pub bg_block_bitmap: u32,
    /// Block number of the inode bitmap.
    pub bg_inode_bitmap: u32,
    /// Block number of the first inode table block.
    pub bg_inode_table: u32,
    /// Number of free blocks in this group.
    pub bg_free_blocks_count: u16,
    /// Number of free inodes in this group.
    pub bg_free_inodes_count: u16,
    /// Number of directories in this group.
    pub bg_used_dirs_count: u16,
}

impl BlockGroupDesc {
    /// Parse a block group descriptor from a 32-byte buffer.
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

/// ext2 inode (on-disk, 128 bytes minimum).
#[derive(Debug, Clone, Copy)]
pub struct Ext2Inode {
    /// File mode (type + permissions).
    pub i_mode: u16,
    /// Owner UID.
    pub i_uid: u16,
    /// File size (lower 32 bits).
    pub i_size: u32,
    /// Last access time (POSIX timestamp).
    pub i_atime: u32,
    /// Creation time.
    pub i_ctime: u32,
    /// Last modification time.
    pub i_mtime: u32,
    /// Hard link count.
    pub i_links_count: u16,
    /// Number of 512-byte sectors allocated.
    pub i_blocks: u32,
    /// Block pointers (12 direct + 1 indirect + 1 double-indirect + 1 triple-indirect).
    pub i_block: [u32; 15],
}

impl Ext2Inode {
    /// Parse an inode from a buffer (at least 128 bytes).
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 128 {
            return Err(Error::InvalidArgument);
        }
        let mut i_block = [0u32; 15];
        for (i, b) in i_block.iter_mut().enumerate() {
            *b = read_u32(buf, 40 + i * 4);
        }
        Ok(Self {
            i_mode: read_u16(buf, 0),
            i_uid: read_u16(buf, 2),
            i_size: read_u32(buf, 4),
            i_atime: read_u32(buf, 8),
            i_ctime: read_u32(buf, 12),
            i_mtime: read_u32(buf, 16),
            i_links_count: read_u16(buf, 26),
            i_blocks: read_u32(buf, 28),
            i_block,
        })
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

    /// File size in bytes.
    pub fn size(&self) -> u64 {
        self.i_size as u64
    }

    /// POSIX permission bits (lower 12 bits of i_mode).
    pub fn permissions(&self) -> u16 {
        self.i_mode & 0x0FFF
    }
}

/// A directory entry read from ext2.
#[derive(Debug, Clone)]
pub struct Ext2DirEntry {
    /// Inode number.
    pub inode: u32,
    /// File name (up to 255 bytes).
    pub name: [u8; EXT2_NAME_LEN],
    /// Name length.
    pub name_len: u8,
    /// File type indicator (from dir entry, if rev >= 0.5).
    pub file_type: u8,
}

impl Ext2DirEntry {
    /// File name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

/// Result of reading a directory.
pub struct DirEntries {
    /// Directory entries.
    pub entries: [Option<Ext2DirEntry>; MAX_DIR_ENTRIES],
    /// Number of entries.
    pub count: usize,
}

impl DirEntries {
    fn new() -> Self {
        const NONE: Option<Ext2DirEntry> = None;
        Self {
            entries: [NONE; MAX_DIR_ENTRIES],
            count: 0,
        }
    }

    fn push(&mut self, entry: Ext2DirEntry) -> Result<()> {
        if self.count >= MAX_DIR_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = Some(entry);
        self.count += 1;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ext2 filesystem driver
// ---------------------------------------------------------------------------

/// Maximum block groups we support.
const MAX_BLOCK_GROUPS: usize = 64;

/// Read-only ext2 filesystem.
///
/// Operates over a `BlockReader` to access the underlying block device.
/// All operations are read-only; write support is not implemented.
pub struct Ext2Fs<R: BlockReader> {
    /// Block reader (storage backend).
    reader: R,
    /// Parsed superblock.
    sb: Ext2Superblock,
    /// Block group descriptors.
    bgd: [Option<BlockGroupDesc>; MAX_BLOCK_GROUPS],
    /// Number of block groups.
    bg_count: usize,
}

impl<R: BlockReader> Ext2Fs<R> {
    /// Mount an ext2 filesystem from the given block reader.
    ///
    /// Reads and validates the superblock and block group descriptors.
    pub fn mount(reader: R) -> Result<Self> {
        // Read superblock (at offset 1024, 1024 bytes).
        let mut sb_buf = [0u8; 1024];
        reader.read_bytes(SUPERBLOCK_OFFSET, &mut sb_buf)?;
        let sb = Ext2Superblock::from_bytes(&sb_buf)?;

        let block_size = sb.block_size();
        if block_size > MAX_BLOCK_SIZE {
            return Err(Error::InvalidArgument);
        }

        let bg_count = sb.block_group_count() as usize;
        if bg_count > MAX_BLOCK_GROUPS {
            return Err(Error::OutOfMemory);
        }

        // Block group descriptor table starts at the block after the superblock.
        // For 1K blocks, superblock is in block 1, BGD in block 2.
        // For >=2K blocks, superblock is in block 0 (offset 1024), BGD in block 1.
        let bgd_block = if block_size == 1024 { 2 } else { 1 };
        let bgd_offset = bgd_block * block_size;

        const NONE_BGD: Option<BlockGroupDesc> = None;
        let mut bgd = [NONE_BGD; MAX_BLOCK_GROUPS];

        // Read each 32-byte BGD entry.
        let mut bgd_buf = [0u8; 32];
        for (i, slot) in bgd.iter_mut().enumerate().take(bg_count) {
            let offset = bgd_offset + (i as u64 * 32);
            reader.read_bytes(offset, &mut bgd_buf)?;
            *slot = Some(BlockGroupDesc::from_bytes(&bgd_buf)?);
        }

        Ok(Self {
            reader,
            sb,
            bgd,
            bg_count,
        })
    }

    /// Return the parsed superblock.
    pub fn superblock(&self) -> &Ext2Superblock {
        &self.sb
    }

    /// Block size in bytes.
    pub fn block_size(&self) -> u64 {
        self.sb.block_size()
    }

    /// Read a raw block into `buf`.
    ///
    /// `buf` must be at least `block_size()` bytes.
    pub fn read_block(&self, block_num: u32, buf: &mut [u8]) -> Result<()> {
        let offset = block_num as u64 * self.block_size();
        let len = self.block_size() as usize;
        if buf.len() < len {
            return Err(Error::InvalidArgument);
        }
        self.reader.read_bytes(offset, &mut buf[..len])
    }

    /// Read an inode by number.
    pub fn read_inode(&self, ino: u32) -> Result<Ext2Inode> {
        if ino == 0 {
            return Err(Error::InvalidArgument);
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

        let mut buf = [0u8; 256]; // max inode size we handle
        let read_len = (inode_size as usize).min(buf.len());
        self.reader.read_bytes(offset, &mut buf[..read_len])?;
        Ext2Inode::from_bytes(&buf[..read_len])
    }

    /// Read the root directory inode.
    pub fn root_inode(&self) -> Result<Ext2Inode> {
        self.read_inode(EXT2_ROOT_INO)
    }

    /// Resolve a block index within a file (direct or single-indirect).
    ///
    /// Returns the on-disk block number, or 0 for a hole (sparse file).
    fn resolve_block(&self, inode: &Ext2Inode, file_block: u32) -> Result<u32> {
        let fb = file_block as usize;
        if fb >= MAX_ADDRESSABLE_BLOCKS {
            return Err(Error::InvalidArgument);
        }

        if fb < EXT2_NDIR_BLOCKS {
            // Direct block.
            return Ok(inode.i_block[fb]);
        }

        // Single-indirect block.
        let indirect_idx = fb - EXT2_NDIR_BLOCKS;
        let indirect_block = inode.i_block[EXT2_IND_BLOCK];
        if indirect_block == 0 {
            return Ok(0); // hole
        }

        // Read the indirect block (array of u32 block numbers).
        let bs = self.block_size() as usize;
        let ptrs_per_block = bs / 4;
        if indirect_idx >= ptrs_per_block {
            return Err(Error::InvalidArgument);
        }

        // We only need 4 bytes at the right offset within the indirect block.
        let offset = indirect_block as u64 * self.block_size() + indirect_idx as u64 * 4;
        let mut buf = [0u8; 4];
        self.reader.read_bytes(offset, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Read file data from an inode.
    ///
    /// Reads up to `buf.len()` bytes starting at `offset` within the file.
    /// Returns the number of bytes actually read.
    pub fn read_file(&self, inode: &Ext2Inode, offset: u64, buf: &mut [u8]) -> Result<usize> {
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

            let disk_block = self.resolve_block(inode, file_block)?;
            if disk_block == 0 {
                // Hole — fill with zeros.
                for b in &mut buf[bytes_read..bytes_read + chunk] {
                    *b = 0;
                }
            } else {
                let disk_offset = disk_block as u64 * bs + block_offset as u64;
                self.reader
                    .read_bytes(disk_offset, &mut buf[bytes_read..bytes_read + chunk])?;
            }

            bytes_read += chunk;
            file_offset += chunk as u64;
        }

        Ok(bytes_read)
    }

    /// Read all directory entries from a directory inode.
    pub fn read_dir(&self, inode: &Ext2Inode) -> Result<DirEntries> {
        if inode.file_type() != Some(crate::inode::FileType::Directory) {
            return Err(Error::InvalidArgument);
        }

        let mut result = DirEntries::new();
        let dir_size = inode.size();
        let mut offset = 0u64;

        while offset < dir_size {
            // Read dir entry header (8 bytes: inode(4) + rec_len(2) + name_len(1) + file_type(1)).
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
                break; // prevent infinite loop on corrupt data
            }

            if entry_inode != 0 && name_len > 0 {
                let mut entry = Ext2DirEntry {
                    inode: entry_inode,
                    name: [0u8; EXT2_NAME_LEN],
                    name_len,
                    file_type: file_type_indicator,
                };

                // Read the name.
                let nl = name_len as usize;
                if nl <= EXT2_NAME_LEN {
                    self.read_file(inode, offset + 8, &mut entry.name[..nl])?;
                }

                // Ignore errors from full result buffer — just return what fits.
                let _ = result.push(entry);
            }

            offset += rec_len;
        }

        Ok(result)
    }

    /// Look up a file by name in a directory inode.
    ///
    /// Returns the inode number if found.
    pub fn lookup(&self, dir_inode: &Ext2Inode, name: &[u8]) -> Result<u32> {
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
    pub fn resolve_path(&self, path: &[u8]) -> Result<Ext2Inode> {
        let mut current = self.read_inode(EXT2_ROOT_INO)?;

        for component in PathComponents::new(path) {
            if component.is_empty() {
                continue;
            }
            let ino = self.lookup(&current, component)?;
            current = self.read_inode(ino)?;
        }

        Ok(current)
    }
}

impl<R: BlockReader> core::fmt::Debug for Ext2Fs<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ext2Fs")
            .field("block_size", &self.block_size())
            .field("blocks", &self.sb.s_blocks_count)
            .field("inodes", &self.sb.s_inodes_count)
            .field("block_groups", &self.bg_count)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Path component iterator
// ---------------------------------------------------------------------------

/// Simple path component iterator (splits on `/`).
struct PathComponents<'a> {
    remaining: &'a [u8],
}

impl<'a> PathComponents<'a> {
    fn new(path: &'a [u8]) -> Self {
        Self { remaining: path }
    }
}

impl<'a> Iterator for PathComponents<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        // Skip leading slashes.
        while self.remaining.first() == Some(&b'/') {
            self.remaining = &self.remaining[1..];
        }
        if self.remaining.is_empty() {
            return None;
        }
        // Find next slash or end.
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
