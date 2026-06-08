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

/// Maximum directory data we will scan in a single readdir (8 MiB).
///
/// Real directories rarely exceed a few hundred KiB.  An attacker-controlled
/// i_size (up to 2^32-1) with minimal rec_len entries would otherwise spin the
/// walk for hundreds of millions of iterations at ring-0.
const MAX_DIR_SCAN: u64 = 8 * 1024 * 1024;

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

        // Validate magic before anything else.
        let magic = read_u16(buf, 56);
        if magic != EXT2_MAGIC {
            return Err(Error::InvalidArgument);
        }

        // [CRITICAL] s_log_block_size: 1024 << n must not overflow u64.
        // Maximum useful shift is 6 (64 KiB); reject anything larger.
        let s_log_block_size = read_u32(buf, 24);
        if s_log_block_size > 6 {
            return Err(Error::InvalidArgument);
        }

        let s_blocks_per_group = read_u32(buf, 32);
        let s_inodes_per_group = read_u32(buf, 40);

        // [CRITICAL] Both fields are used as divisors; 0 causes a kernel halt.
        if s_blocks_per_group == 0 || s_inodes_per_group == 0 {
            return Err(Error::InvalidArgument);
        }

        // SECURITY: s_blocks_count == 0 is a degenerate superblock — every
        // `blk < s_blocks_count` block-range guard downstream would reject all
        // blocks (an unmountable image). Reject it here in the LIVE mount
        // parser so the block-bound checks operate on a real total.
        if read_u32(buf, 4) == 0 {
            return Err(Error::InvalidArgument);
        }

        let s_rev_level = read_u32(buf, 76);
        let s_inode_size = if s_rev_level >= 1 {
            // [HIGH] rev >= 1 carries inode size at offset 88.
            // Must be power-of-two in [128, 1024] and fit inside a block.
            let raw = read_u16(buf, 88);
            if !(128u16..=1024).contains(&raw) || (raw & (raw - 1)) != 0 {
                return Err(Error::InvalidArgument);
            }
            raw
        } else {
            128u16
        };

        Ok(Self {
            s_inodes_count: read_u32(buf, 0),
            s_blocks_count: read_u32(buf, 4),
            s_free_blocks_count: read_u32(buf, 12),
            s_free_inodes_count: read_u32(buf, 16),
            s_first_data_block: read_u32(buf, 20),
            s_log_block_size,
            s_blocks_per_group,
            s_inodes_per_group,
            s_magic: magic,
            s_inode_size,
            s_rev_level,
        })
    }

    /// Computed block size in bytes.
    ///
    /// Safe: `s_log_block_size` is validated to be <= 6 in `from_bytes`.
    pub fn block_size(&self) -> u64 {
        // SAFETY: shift amount is bounded to [0, 6] by from_bytes validation.
        BASE_BLOCK_SIZE << self.s_log_block_size
    }

    /// Number of block groups.
    ///
    /// Safe: `s_blocks_per_group` is validated to be non-zero in `from_bytes`.
    pub fn block_group_count(&self) -> u32 {
        // s_blocks_per_group != 0 is guaranteed by from_bytes.
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
        // SECURITY: use checked arithmetic so that a large bg_count (bounded
        // to MAX_BLOCK_GROUPS=64) combined with a large bgd_offset cannot
        // silently overflow to a wrong device offset.
        let mut bgd_buf = [0u8; 32];
        for (i, slot) in bgd.iter_mut().enumerate().take(bg_count) {
            let entry_off = (i as u64)
                .checked_mul(32)
                .and_then(|o| bgd_offset.checked_add(o))
                .ok_or(Error::InvalidArgument)?;
            reader.read_bytes(entry_off, &mut bgd_buf)?;
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
        // SECURITY: block_num == 0 is a hole/unallocated sentinel in ext2;
        // reject rather than reading the boot sector at offset 0.
        if block_num == 0 {
            return Err(Error::InvalidArgument);
        }
        // SECURITY: bound block_num against the superblock total before
        // converting to a byte offset.  An attacker-controlled block number
        // >= s_blocks_count would produce an OOB read of kernel memory.
        if block_num >= self.sb.s_blocks_count {
            return Err(Error::InvalidArgument);
        }
        // SECURITY: use checked_mul so that a crafted block_size (bounded to
        // <= 64 KiB) combined with a large block_num cannot overflow u64.
        let offset = (block_num as u64)
            .checked_mul(self.block_size())
            .ok_or(Error::InvalidArgument)?;
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

        // [CRITICAL] s_inodes_per_group != 0 guaranteed by from_bytes, but
        // use checked_div defensively to prevent any future regression.
        let group = idx
            .checked_div(self.sb.s_inodes_per_group)
            .ok_or(Error::InvalidArgument)? as usize;
        let local_idx = idx % self.sb.s_inodes_per_group;

        if group >= self.bg_count {
            return Err(Error::NotFound);
        }
        let bgd = self.bgd[group].as_ref().ok_or(Error::NotFound)?;

        let inode_size = self.sb.s_inode_size as u64;
        let block_size = self.block_size();

        // SECURITY: bg_inode_table is an attacker-supplied u32 block number.
        // Validate it against s_blocks_count before using as a device offset.
        // A value of 0 or >= s_blocks_count means a corrupt/malicious image.
        if bgd.bg_inode_table == 0 || bgd.bg_inode_table >= self.sb.s_blocks_count {
            return Err(Error::InvalidArgument);
        }

        // SECURITY: use checked arithmetic to prevent wrap-around on
        // attacker-controlled on-disk fields.
        let table_offset = (bgd.bg_inode_table as u64)
            .checked_mul(block_size)
            .ok_or(Error::InvalidArgument)?;
        let local_offset = (local_idx as u64)
            .checked_mul(inode_size)
            .ok_or(Error::InvalidArgument)?;
        let offset = table_offset
            .checked_add(local_offset)
            .ok_or(Error::InvalidArgument)?;

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
            // Direct block — validate before returning to callers.
            let blk = inode.i_block[fb];
            // SECURITY: block 0 is a valid sparse-file hole; any non-zero
            // block number must be within the filesystem's total block count.
            if blk != 0 && blk >= self.sb.s_blocks_count {
                return Err(Error::InvalidArgument);
            }
            return Ok(blk);
        }

        // Single-indirect block.
        let indirect_idx = fb - EXT2_NDIR_BLOCKS;
        let indirect_block = inode.i_block[EXT2_IND_BLOCK];
        if indirect_block == 0 {
            return Ok(0); // hole
        }

        // SECURITY: validate the indirect block pointer itself before using it
        // as a device offset.  An attacker-controlled value >= s_blocks_count
        // would produce an OOB read of kernel memory.
        if indirect_block >= self.sb.s_blocks_count {
            return Err(Error::InvalidArgument);
        }

        // Read the indirect block (array of u32 block numbers).
        let bs = self.block_size() as usize;
        let ptrs_per_block = bs / 4;
        if indirect_idx >= ptrs_per_block {
            return Err(Error::InvalidArgument);
        }

        // SECURITY: use checked arithmetic for the indirect block byte offset.
        let indirect_byte_off = (indirect_block as u64)
            .checked_mul(self.block_size())
            .ok_or(Error::InvalidArgument)?;
        let ptr_byte_off = (indirect_idx as u64)
            .checked_mul(4)
            .ok_or(Error::InvalidArgument)?;
        let offset = indirect_byte_off
            .checked_add(ptr_byte_off)
            .ok_or(Error::InvalidArgument)?;
        let mut buf = [0u8; 4];
        self.reader.read_bytes(offset, &mut buf)?;
        let data_block = u32::from_le_bytes(buf);

        // SECURITY: validate the resolved data block pointer against
        // s_blocks_count before returning it to callers that will use it as a
        // device offset.  Block 0 is a valid sparse hole and is allowed.
        if data_block != 0 && data_block >= self.sb.s_blocks_count {
            return Err(Error::InvalidArgument);
        }
        Ok(data_block)
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
                // SECURITY: disk_block is already validated < s_blocks_count by
                // resolve_block; use checked arithmetic here to guard against
                // any future regression and to prevent overflow on the final
                // byte offset (disk_block * block_size + block_offset).
                let disk_offset = (disk_block as u64)
                    .checked_mul(bs)
                    .and_then(|o| o.checked_add(block_offset as u64))
                    .ok_or(Error::InvalidArgument)?;
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
        // Cap the scan to MAX_DIR_SCAN bytes.  i_size can be up to 2^32-1 on
        // an untrusted image; without the cap an attacker can drive the loop
        // for hundreds of millions of iterations at ring-0.
        let dir_size = inode.size().min(MAX_DIR_SCAN);
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

            // [HIGH] Validate rec_len to prevent CPU-DoS from tiny or
            // misaligned entries that advance offset by < 8 bytes per
            // iteration over the full dir_size-sized loop.
            // Minimum valid entry: 8-byte header + 4-byte aligned name.
            // Also guard against offset + rec_len wrapping past dir_size.
            if rec_len < 8 || (rec_len & 3) != 0 {
                break; // corrupt entry — stop safely
            }
            let next_offset = match offset.checked_add(rec_len) {
                Some(n) if n <= dir_size => n,
                _ => break, // would overflow or exceed directory data
            };

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

            offset = next_offset;
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

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Synthetic blob builder
    //
    // Layout (1 KiB blocks, 8 KiB image = 8 blocks):
    //
    //   Block 0   (0x0000): boot / unused
    //   Block 1   (0x0400): superblock
    //   Block 2   (0x0800): block group descriptor table
    //   Block 3   (0x0C00): block bitmap
    //   Block 4   (0x1000): inode bitmap
    //   Block 5   (0x1400): inode table (inodes 1-16, 128 bytes each)
    //   Block 6   (0x1800): root directory data (inode 2)
    //   Block 7   (0x1C00): hello.txt file data (inode 3)
    //
    // Inode numbering (1-based):
    //   Inode 1 — reserved (bad blocks)
    //   Inode 2 — root directory
    //   Inode 3 — hello.txt regular file
    // -----------------------------------------------------------------------

    const BLOCK_SIZE: usize = 1024;
    const IMAGE_BLOCKS: usize = 8;
    const IMAGE_SIZE: usize = IMAGE_BLOCKS * BLOCK_SIZE;
    const INODES_PER_GROUP: u32 = 16;
    const BLOCKS_PER_GROUP: u32 = IMAGE_BLOCKS as u32;
    const INODE_TABLE_BLOCK: u32 = 5;
    const ROOT_DIR_BLOCK: u32 = 6;
    const HELLO_DATA_BLOCK: u32 = 7;
    const HELLO_CONTENT: &[u8] = b"ext2 root\n";

    /// Write a little-endian u16 into a buffer.
    fn w16(buf: &mut [u8], off: usize, v: u16) {
        let b = v.to_le_bytes();
        buf[off] = b[0];
        buf[off + 1] = b[1];
    }

    /// Write a little-endian u32 into a buffer.
    fn w32(buf: &mut [u8], off: usize, v: u32) {
        let b = v.to_le_bytes();
        buf[off] = b[0];
        buf[off + 1] = b[1];
        buf[off + 2] = b[2];
        buf[off + 3] = b[3];
    }

    /// Build a synthetic 8 KiB ext2 image on the stack.
    fn build_image() -> [u8; IMAGE_SIZE] {
        let mut img = [0u8; IMAGE_SIZE];

        // ── Superblock at offset 1024 (block 1) ────────────────────────────
        let sb = &mut img[1024..2048];
        w32(sb, 0, 16); // s_inodes_count
        w32(sb, 4, BLOCKS_PER_GROUP); // s_blocks_count
        w32(sb, 8, 0); // s_r_blocks_count
        w32(sb, 12, BLOCKS_PER_GROUP - 8); // s_free_blocks_count
        w32(sb, 16, INODES_PER_GROUP - 3); // s_free_inodes_count
        w32(sb, 20, 1); // s_first_data_block (1 for 1K blocks)
        w32(sb, 24, 0); // s_log_block_size = 0 → 1024 bytes
        w32(sb, 28, 0); // s_log_frag_size
        w32(sb, 32, BLOCKS_PER_GROUP); // s_blocks_per_group
        w32(sb, 36, BLOCKS_PER_GROUP); // s_frags_per_group
        w32(sb, 40, INODES_PER_GROUP); // s_inodes_per_group
        w32(sb, 76, 0); // s_rev_level = 0 (inode size = 128)
        w16(sb, 56, 0xEF53); // s_magic

        // ── Block group descriptor at block 2 (offset 2048) ─────────────
        let bgd = &mut img[2048..2048 + 32];
        w32(bgd, 0, 3); // bg_block_bitmap → block 3
        w32(bgd, 4, 4); // bg_inode_bitmap → block 4
        w32(bgd, 8, INODE_TABLE_BLOCK); // bg_inode_table → block 5
        w16(bgd, 12, (BLOCKS_PER_GROUP - 8) as u16); // bg_free_blocks_count
        w16(bgd, 14, (INODES_PER_GROUP - 3) as u16); // bg_free_inodes_count
        w16(bgd, 16, 1); // bg_used_dirs_count

        // ── Inode table at block 5 (offset 5120) ────────────────────────
        // Each inode is 128 bytes; inode N is at local index N-1.
        let it_base = INODE_TABLE_BLOCK as usize * BLOCK_SIZE;

        // Inode 2 — root directory (type=dir, mode=0o40755)
        {
            let ino = &mut img[it_base + 128..it_base + 256]; // local index 1
            w16(ino, 0, 0x4000 | 0o755); // i_mode: directory + rwxr-xr-x
            w16(ino, 2, 0); // i_uid
            w32(ino, 4, BLOCK_SIZE as u32); // i_size = 1 block
            w32(ino, 8, 0); // i_atime
            w32(ino, 12, 0); // i_ctime
            w32(ino, 16, 0); // i_mtime
            w16(ino, 26, 2); // i_links_count
            w32(ino, 28, 2); // i_blocks (512-byte units)
            w32(ino, 40, ROOT_DIR_BLOCK); // i_block[0] = block 6
        }

        // Inode 3 — hello.txt regular file (type=reg, mode=0o100644)
        {
            let ino = &mut img[it_base + 256..it_base + 384]; // local index 2
            w16(ino, 0, 0x8000 | 0o644); // i_mode: regular + rw-r--r--
            w16(ino, 2, 0); // i_uid
            w32(ino, 4, HELLO_CONTENT.len() as u32); // i_size
            w32(ino, 8, 0); // i_atime
            w32(ino, 12, 0); // i_ctime
            w32(ino, 16, 0); // i_mtime
            w16(ino, 26, 1); // i_links_count
            w32(ino, 28, 2); // i_blocks (512-byte units)
            w32(ino, 40, HELLO_DATA_BLOCK); // i_block[0] = block 7
        }

        // ── Root directory block at block 6 (offset 6144) ───────────────
        // Two entries: "." (inode 2) and "hello.txt" (inode 3).
        {
            let dir = &mut img[ROOT_DIR_BLOCK as usize * BLOCK_SIZE..];

            // Entry 0: "." → inode 2
            // Layout: inode(4) + rec_len(2) + name_len(1) + file_type(1) + name
            w32(dir, 0, 2); // inode = 2 (root)
            w16(dir, 4, 12); // rec_len = 12 (4+2+1+1 + 1 byte name padded to 4)
            dir[6] = 1; // name_len = 1
            dir[7] = 2; // file_type = DIR
            dir[8] = b'.';

            // Entry 1: "hello.txt" → inode 3
            let off1 = 12;
            let name = b"hello.txt";
            let name_len = name.len() as u8; // 9
            // rec_len must be rounded to 4-byte boundary:
            // 8 (hdr) + 9 (name) = 17 → rounded up to 20
            let rec_len = ((8 + name_len as usize + 3) & !3) as u16;
            w32(dir, off1, 3); // inode = 3
            w16(dir, off1 + 4, rec_len);
            dir[off1 + 6] = name_len;
            dir[off1 + 7] = 1; // file_type = REG
            dir[off1 + 8..off1 + 8 + name.len()].copy_from_slice(name);

            // Terminal entry: rec_len fills rest of block
            let off2 = off1 + rec_len as usize;
            let remaining = BLOCK_SIZE - off2;
            w32(dir, off2, 0); // inode = 0 (unused)
            w16(dir, off2 + 4, remaining as u16);
        }

        // ── hello.txt data block at block 7 (offset 7168) ───────────────
        {
            let data_off = HELLO_DATA_BLOCK as usize * BLOCK_SIZE;
            img[data_off..data_off + HELLO_CONTENT.len()].copy_from_slice(HELLO_CONTENT);
        }

        img
    }

    /// A `BlockReader` backed by a slice reference.
    struct SliceReader<'a>(&'a [u8]);

    impl<'a> BlockReader for SliceReader<'a> {
        fn read_bytes(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            let start = offset as usize;
            let end = start + buf.len();
            if end > self.0.len() {
                return Err(Error::InvalidArgument);
            }
            buf.copy_from_slice(&self.0[start..end]);
            Ok(())
        }
    }

    // ── Tests ────────────────────────────────────────────────────────────────

    #[test]
    fn ext2_superblock_parsed_correctly() {
        let img = build_image();
        let fs = Ext2Fs::mount(SliceReader(&img)).expect("mount failed");
        let sb = fs.superblock();
        assert_eq!(sb.s_magic, 0xEF53, "magic mismatch");
        assert_eq!(sb.s_inodes_count, 16);
        assert_eq!(sb.s_blocks_count, BLOCKS_PER_GROUP);
        assert_eq!(sb.s_log_block_size, 0);
        assert_eq!(sb.block_size(), 1024);
        assert_eq!(sb.s_inodes_per_group, INODES_PER_GROUP);
        assert_eq!(sb.s_inode_size, 128);
        assert_eq!(sb.s_first_data_block, 1);
    }

    #[test]
    fn ext2_block_group_descriptor_parsed() {
        let img = build_image();
        let fs = Ext2Fs::mount(SliceReader(&img)).expect("mount failed");
        // bg_count must be 1 for a 1 MiB / 1 block group image
        assert_eq!(fs.bg_count, 1);
        let bgd = fs.bgd[0].as_ref().expect("BGD 0 missing");
        assert_eq!(bgd.bg_block_bitmap, 3);
        assert_eq!(bgd.bg_inode_bitmap, 4);
        assert_eq!(bgd.bg_inode_table, INODE_TABLE_BLOCK);
    }

    #[test]
    fn ext2_root_inode_is_directory() {
        let img = build_image();
        let fs = Ext2Fs::mount(SliceReader(&img)).expect("mount failed");
        let root = fs.root_inode().expect("root inode");
        assert_eq!(
            root.file_type(),
            Some(crate::inode::FileType::Directory),
            "root inode must be a directory"
        );
        assert_eq!(root.size(), BLOCK_SIZE as u64);
    }

    #[test]
    fn ext2_hello_txt_found_in_root_dir() {
        let img = build_image();
        let fs = Ext2Fs::mount(SliceReader(&img)).expect("mount failed");
        let root = fs.root_inode().expect("root inode");
        let entries = fs.read_dir(&root).expect("read_dir");

        let hello = entries.entries[..entries.count]
            .iter()
            .flatten()
            .find(|e| e.name() == b"hello.txt")
            .expect("hello.txt entry not found in root directory");

        assert_eq!(hello.inode, 3, "hello.txt inode number");
    }

    #[test]
    fn ext2_hello_txt_data_matches_expected() {
        let img = build_image();
        let fs = Ext2Fs::mount(SliceReader(&img)).expect("mount failed");
        let inode = fs.read_inode(3).expect("read inode 3");
        assert_eq!(
            inode.file_type(),
            Some(crate::inode::FileType::Regular),
            "hello.txt must be a regular file"
        );
        assert_eq!(inode.size(), HELLO_CONTENT.len() as u64);

        let mut buf = [0u8; 16];
        let n = fs
            .read_file(&inode, 0, &mut buf[..HELLO_CONTENT.len()])
            .expect("read_file");
        assert_eq!(n, HELLO_CONTENT.len());
        assert_eq!(&buf[..n], HELLO_CONTENT, "file content mismatch");
    }

    #[test]
    fn ext2_invalid_magic_rejected() {
        let mut img = build_image();
        // Corrupt the magic bytes in the superblock.
        img[1024 + 56] = 0xDE;
        img[1024 + 57] = 0xAD;
        assert!(
            Ext2Fs::mount(SliceReader(&img)).is_err(),
            "mount must fail on bad magic"
        );
    }

    #[test]
    fn ext2_resolve_path_hello_txt() {
        let img = build_image();
        let fs = Ext2Fs::mount(SliceReader(&img)).expect("mount failed");
        let inode = fs.resolve_path(b"/hello.txt").expect("resolve /hello.txt");
        assert_eq!(inode.file_type(), Some(crate::inode::FileType::Regular));
        assert_eq!(inode.size(), HELLO_CONTENT.len() as u64);
    }
}
