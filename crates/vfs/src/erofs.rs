// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! EROFS (Enhanced Read-Only File System) driver.
//!
//! EROFS is a read-only filesystem designed for high-performance access
//! with random-access characteristics. It is used in Android system images
//! and Linux distributions that need efficient compressed read-only storage.
//!
//! # Architecture
//!
//! ```text
//! ErofsSuperblock  (1024 bytes at block 0)
//!   → inode table  (meta_blkaddr, compact 32B or extended 64B)
//!     → ErofsInode  (format, mode, size, data_layout, blkaddr)
//!       → data blocks (flat-plain, flat-inline, chunk-based)
//!   → directory table
//!     → DirectoryEntry (nid, name_off, file_type, name)
//! ```
//!
//! # Structures
//!
//! - [`InodeFormat`] — compact (32B) vs extended (64B) inode
//! - [`DataLayout`] — how file data is stored (plain, inline, chunk, compressed)
//! - [`ErofsSuperblock`] — on-disk superblock at block 0
//! - [`ErofsInode`] — parsed inode metadata
//! - [`DirectoryEntry`] — directory listing entry
//! - [`CompressedIndex`] — cluster descriptor for compressed layout
//! - [`ErofsFs`] — mounted filesystem handle

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────

/// EROFS superblock magic number.
pub const EROFS_MAGIC: u32 = 0xE0F5_E1E2;

/// EROFS superblock offset within the first block (1024 bytes).
const SUPERBLOCK_OFFSET: usize = 1024;

/// Minimum superblock size we need to read (bytes).
const SUPERBLOCK_SIZE: usize = 128;

/// Block size shift used when block_size_bits is not specified (default 12 = 4K).
const DEFAULT_BLOCK_SIZE_LOG: u32 = 12;

/// Maximum directory entries returned by [`ErofsFs::readdir`].
const MAX_DIR_ENTRIES: usize = 128;

/// Maximum file name length in bytes.
const MAX_NAME_LEN: usize = 256;

/// Compact inode size in bytes.
const COMPACT_INODE_SIZE: usize = 32;

/// Extended inode size in bytes.
const EXTENDED_INODE_SIZE: usize = 64;

/// EROFS directory entry size (fixed header, 12 bytes).
const DIRENT_HDR_SIZE: usize = 12;

// ── InodeFormat ──────────────────────────────────────────────────

/// EROFS inode format selector.
///
/// Compact inodes occupy 32 bytes on disk and hold 32-bit timestamps.
/// Extended inodes occupy 64 bytes and hold 64-bit nanosecond timestamps
/// plus extra fields for large files and xattrs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeFormat {
    /// 32-byte compact inode (version 1).
    Compact,
    /// 64-byte extended inode (version 2).
    Extended,
}

impl InodeFormat {
    /// Determine the inode format from the on-disk format field.
    ///
    /// The low bit of the `i_format` field selects the format (0 = compact,
    /// 1 = extended). Returns `None` for invalid values.
    pub fn from_raw(raw: u16) -> Option<Self> {
        match raw & 0x001F {
            0 => Some(Self::Compact),
            1 => Some(Self::Extended),
            _ => None,
        }
    }

    /// Size of this inode format in bytes.
    pub fn size(self) -> usize {
        match self {
            Self::Compact => COMPACT_INODE_SIZE,
            Self::Extended => EXTENDED_INODE_SIZE,
        }
    }
}

// ── DataLayout ───────────────────────────────────────────────────

/// EROFS data layout for a file.
///
/// Controls how the file's data blocks are addressed and potentially
/// compressed. Stored in the upper bits of the `i_format` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataLayout {
    /// Plain layout: data stored in contiguous blocks starting at `raw_blkaddr`.
    FlatPlain,
    /// Inline layout: data stored within the inode's tail area (small files).
    FlatInline,
    /// Chunk-based layout: file uses a chunk index for block mapping.
    ChunkBased,
    /// Compressed layout: data uses per-cluster compression.
    Compressed,
}

impl DataLayout {
    /// Parse the data layout from the upper bits of `i_format`.
    pub fn from_raw(raw: u16) -> Self {
        match (raw >> 5) & 0x7 {
            0 => Self::FlatPlain,
            1 => Self::FlatInline,
            2 => Self::ChunkBased,
            3 => Self::Compressed,
            _ => Self::FlatPlain,
        }
    }
}

// ── ErofsSuperblock ──────────────────────────────────────────────

/// EROFS on-disk superblock.
///
/// Located at byte offset 1024 within the first block. All multi-byte
/// fields are little-endian.
#[derive(Debug, Clone, Copy)]
pub struct ErofsSuperblock {
    /// Magic number — must equal [`EROFS_MAGIC`].
    pub magic: u32,
    /// CRC32C checksum of the superblock (may be 0 if feature not enabled).
    pub checksum: u32,
    /// Feature compatibility flags.
    pub feature_compat: u32,
    /// Block size as a power-of-two exponent (block_size = 1 << blkszbits).
    pub blkszbits: u8,
    /// Superblock flags (upper bits of the root_nid extension).
    pub sb_extslots: u8,
    /// Root directory nid (inode number).
    pub root_nid: u16,
    /// Total number of inodes.
    pub inos: u64,
    /// Filesystem creation timestamp (seconds since epoch).
    pub build_time: u64,
    /// Filesystem creation timestamp (nanoseconds).
    pub build_time_nsec: u32,
    /// Total number of blocks.
    pub blocks: u32,
    /// Block address of the metadata area.
    pub meta_blkaddr: u32,
    /// Block address of the xattr area.
    pub xattr_blkaddr: u32,
    /// UUID of the filesystem.
    pub uuid: [u8; 16],
    /// Volume label (null-terminated).
    pub volume_name: [u8; 16],
    /// Incompatible feature flags.
    pub feature_incompat: u32,
    /// Union field: compression algorithm or chunk format.
    pub compression: u16,
    /// Extra devices count.
    pub extra_devices: u16,
    /// Devt slot size in blocks.
    pub devt_slotoff: u16,
}

impl ErofsSuperblock {
    /// Parse an EROFS superblock from the image.
    ///
    /// Reads from offset 1024 within `data`. Returns `InvalidArgument` if
    /// the buffer is too small or the magic is wrong.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < SUPERBLOCK_OFFSET + SUPERBLOCK_SIZE {
            return Err(Error::InvalidArgument);
        }

        let d = &data[SUPERBLOCK_OFFSET..];

        let magic = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
        if magic != EROFS_MAGIC {
            return Err(Error::InvalidArgument);
        }

        let checksum = u32::from_le_bytes([d[4], d[5], d[6], d[7]]);
        let feature_compat = u32::from_le_bytes([d[8], d[9], d[10], d[11]]);
        let blkszbits = d[12];
        let sb_extslots = d[13];
        let root_nid = u16::from_le_bytes([d[14], d[15]]);
        let inos = u64::from_le_bytes([d[16], d[17], d[18], d[19], d[20], d[21], d[22], d[23]]);
        let build_time =
            u64::from_le_bytes([d[24], d[25], d[26], d[27], d[28], d[29], d[30], d[31]]);
        let build_time_nsec = u32::from_le_bytes([d[32], d[33], d[34], d[35]]);
        let blocks = u32::from_le_bytes([d[36], d[37], d[38], d[39]]);
        let meta_blkaddr = u32::from_le_bytes([d[40], d[41], d[42], d[43]]);
        let xattr_blkaddr = u32::from_le_bytes([d[44], d[45], d[46], d[47]]);

        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&d[48..64]);

        let mut volume_name = [0u8; 16];
        volume_name.copy_from_slice(&d[64..80]);

        let feature_incompat = u32::from_le_bytes([d[80], d[81], d[82], d[83]]);
        let compression = u16::from_le_bytes([d[84], d[85]]);
        let extra_devices = u16::from_le_bytes([d[86], d[87]]);
        let devt_slotoff = u16::from_le_bytes([d[88], d[89]]);

        Ok(Self {
            magic,
            checksum,
            feature_compat,
            blkszbits,
            sb_extslots,
            root_nid,
            inos,
            build_time,
            build_time_nsec,
            blocks,
            meta_blkaddr,
            xattr_blkaddr,
            uuid,
            volume_name,
            feature_incompat,
            compression,
            extra_devices,
            devt_slotoff,
        })
    }

    /// Return the block size in bytes.
    pub fn block_size(&self) -> u32 {
        let bits = if self.blkszbits == 0 {
            DEFAULT_BLOCK_SIZE_LOG
        } else {
            self.blkszbits as u32
        };
        1u32 << bits
    }
}

// ── ErofsInode ───────────────────────────────────────────────────

/// EROFS parsed inode.
///
/// Merges compact and extended inode fields into a single structure for
/// uniform access. Fields not present in compact inodes default to zero.
#[derive(Debug, Clone, Copy)]
pub struct ErofsInode {
    /// Inode format (compact or extended).
    pub format: InodeFormat,
    /// Data layout.
    pub data_layout: DataLayout,
    /// POSIX permission mode bits (includes file type bits).
    pub mode: u16,
    /// Number of hard links.
    pub nlink: u32,
    /// File size in bytes.
    pub size: u64,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Last modification time (seconds since epoch).
    pub mtime: u64,
    /// Last modification time nanoseconds (extended inodes only).
    pub mtime_nsec: u32,
    /// Raw block address (for FlatPlain/FlatInline layouts).
    pub raw_blkaddr: u32,
    /// Chunk information (for ChunkBased layout): chunk bits and format.
    pub chunk_info: u32,
    /// Number of xattr entries.
    pub xattr_icount: u16,
    /// inode number (nid).
    pub nid: u64,
}

impl ErofsInode {
    /// Create a new inode with sensible defaults.
    pub fn new(nid: u64, format: InodeFormat) -> Self {
        Self {
            format,
            data_layout: DataLayout::FlatPlain,
            mode: 0o644,
            nlink: 1,
            size: 0,
            uid: 0,
            gid: 0,
            mtime: 0,
            mtime_nsec: 0,
            raw_blkaddr: 0,
            chunk_info: 0,
            xattr_icount: 0,
            nid,
        }
    }

    /// Whether this inode represents a regular file.
    pub fn is_file(&self) -> bool {
        (self.mode & 0xF000) == 0x8000
    }

    /// Whether this inode represents a directory.
    pub fn is_dir(&self) -> bool {
        (self.mode & 0xF000) == 0x4000
    }

    /// Whether this inode represents a symbolic link.
    pub fn is_symlink(&self) -> bool {
        (self.mode & 0xF000) == 0xA000
    }
}

// ── DirectoryEntry ───────────────────────────────────────────────

/// EROFS directory entry.
///
/// Entries are densely packed after a 12-byte dirent header. The name
/// is not NUL-terminated on-disk; length is derived from the next entry's
/// `name_off` or the block boundary.
#[derive(Clone, Copy)]
pub struct DirectoryEntry {
    /// Inode number (nid) of the entry.
    pub nid: u64,
    /// Byte offset of the name within the directory block.
    pub name_off: u16,
    /// File type (DT_* constants).
    pub file_type: u8,
    /// Filename bytes.
    pub name: [u8; MAX_NAME_LEN],
    /// Length of the filename in bytes.
    pub name_len: usize,
}

impl DirectoryEntry {
    /// Create an empty directory entry.
    pub fn empty() -> Self {
        Self {
            nid: 0,
            name_off: 0,
            file_type: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
        }
    }

    /// Return the filename as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

impl core::fmt::Debug for DirectoryEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DirectoryEntry")
            .field("nid", &self.nid)
            .field("file_type", &self.file_type)
            .field("name_len", &self.name_len)
            .finish()
    }
}

// ── CompressedIndex ──────────────────────────────────────────────

/// Cluster descriptor for compressed data layout.
///
/// Each cluster index entry describes one compression cluster.
/// The compression algorithm and cluster offset together describe
/// how to decompress a region of the file.
#[derive(Debug, Clone, Copy)]
pub struct CompressedIndex {
    /// Compression algorithm used for this cluster (matches superblock).
    pub compression_algo: u16,
    /// Byte offset of the cluster within its block.
    pub cluster_offset: u16,
    /// Block address of the cluster.
    pub blkaddr: u32,
}

impl CompressedIndex {
    /// Create a new compressed index entry.
    pub fn new(compression_algo: u16, cluster_offset: u16, blkaddr: u32) -> Self {
        Self {
            compression_algo,
            cluster_offset,
            blkaddr,
        }
    }
}

// ── ErofsFs ──────────────────────────────────────────────────────

/// Mounted EROFS filesystem handle.
///
/// Holds the parsed superblock and a reference to the raw filesystem image.
/// All read operations work directly on the image slice.
pub struct ErofsFs<'a> {
    /// Parsed superblock.
    pub superblock: ErofsSuperblock,
    /// Raw filesystem image.
    data: &'a [u8],
    /// Cached block size in bytes.
    block_size: u32,
}

impl<'a> ErofsFs<'a> {
    /// Mount an EROFS filesystem from the given byte slice.
    ///
    /// Parses the superblock and validates the magic. Returns
    /// `InvalidArgument` if the image is malformed.
    pub fn mount(data: &'a [u8]) -> Result<Self> {
        let superblock = ErofsSuperblock::parse(data)?;
        let block_size = superblock.block_size();
        Ok(Self {
            superblock,
            data,
            block_size,
        })
    }

    /// Compute the byte offset in the image for a given nid.
    ///
    /// nid addresses 32-byte slots within the metadata area starting at
    /// `meta_blkaddr`.
    fn nid_to_offset(&self, nid: u64) -> usize {
        let meta_start = self.superblock.meta_blkaddr as u64 * self.block_size as u64;
        // Each nid slot is 32 bytes (compact inode slot size).
        (meta_start + nid * 32) as usize
    }

    /// Read the inode identified by `nid`.
    ///
    /// Parses either a compact or extended inode depending on the format
    /// bit in `i_format`. Returns `NotFound` if the nid is zero or out of
    /// range, or `IoError` if the image is truncated.
    pub fn read_inode(&self, nid: u64) -> Result<ErofsInode> {
        if nid == 0 {
            return Err(Error::NotFound);
        }

        let off = self.nid_to_offset(nid);
        if off + 2 > self.data.len() {
            return Err(Error::IoError);
        }

        let d = &self.data[off..];
        let i_format = u16::from_le_bytes([d[0], d[1]]);
        let format = InodeFormat::from_raw(i_format).ok_or(Error::InvalidArgument)?;
        let data_layout = DataLayout::from_raw(i_format);

        if off + format.size() > self.data.len() {
            return Err(Error::IoError);
        }

        let mode = u16::from_le_bytes([d[2], d[3]]);
        let xattr_icount = u16::from_le_bytes([d[4], d[5]]);

        let mut inode = ErofsInode::new(nid, format);
        inode.data_layout = data_layout;
        inode.mode = mode;
        inode.xattr_icount = xattr_icount;

        match format {
            InodeFormat::Compact => {
                // Compact inode (32 bytes):
                // [0..2]  i_format
                // [2..4]  i_mode
                // [4..6]  i_xattr_icount
                // [6..8]  i_nlink
                // [8..16] i_size (compact: 32-bit low, rest zero? actually 64-bit per spec)
                // [16..20] i_reserved
                // [20..24] raw_blkaddr or chunk_info
                // [24..28] i_uid
                // [28..30] i_gid
                // [30..32] reserved
                inode.nlink = u16::from_le_bytes([d[6], d[7]]) as u32;
                inode.size = u64::from(u32::from_le_bytes([d[8], d[9], d[10], d[11]]));
                inode.raw_blkaddr = u32::from_le_bytes([d[20], d[21], d[22], d[23]]);
                inode.uid = u16::from_le_bytes([d[24], d[25]]) as u32;
                inode.gid = u16::from_le_bytes([d[26], d[27]]) as u32;
            }
            InodeFormat::Extended => {
                // Extended inode (64 bytes):
                // [0..2]  i_format
                // [2..4]  i_mode
                // [4..6]  i_xattr_icount
                // [6..8]  i_nlink (reserved in extended)
                // [8..16] i_size (64-bit)
                // [16..20] i_reserved
                // [20..24] raw_blkaddr or chunk_info
                // [24..32] i_mtime (64-bit)
                // [32..36] i_mtime_nsec
                // [36..40] i_nlink (32-bit in extended)
                // [40..44] i_uid (32-bit)
                // [44..48] i_gid (32-bit)
                // [48..64] reserved
                inode.size =
                    u64::from_le_bytes([d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]]);
                inode.raw_blkaddr = u32::from_le_bytes([d[20], d[21], d[22], d[23]]);
                inode.mtime =
                    u64::from_le_bytes([d[24], d[25], d[26], d[27], d[28], d[29], d[30], d[31]]);
                inode.mtime_nsec = u32::from_le_bytes([d[32], d[33], d[34], d[35]]);
                inode.nlink = u32::from_le_bytes([d[36], d[37], d[38], d[39]]);
                inode.uid = u32::from_le_bytes([d[40], d[41], d[42], d[43]]);
                inode.gid = u32::from_le_bytes([d[44], d[45], d[46], d[47]]);
            }
        }

        Ok(inode)
    }

    /// Read directory entries for the given nid.
    ///
    /// Returns a fixed-size array of up to [`MAX_DIR_ENTRIES`] parsed entries.
    /// Returns `NotFound` if the nid is not a directory, or `IoError` on
    /// image truncation.
    pub fn readdir(&self, nid: u64) -> Result<[DirectoryEntry; MAX_DIR_ENTRIES]> {
        let inode = self.read_inode(nid)?;
        if !inode.is_dir() {
            return Err(Error::NotFound);
        }

        let mut entries = [DirectoryEntry::empty(); MAX_DIR_ENTRIES];
        let mut count = 0usize;

        // Directory data starts at raw_blkaddr.
        let dir_start = inode.raw_blkaddr as usize * self.block_size as usize;
        let dir_size = inode.size as usize;

        if dir_start + dir_size > self.data.len() {
            return Err(Error::IoError);
        }

        let dir_data = &self.data[dir_start..dir_start + dir_size];
        let mut pos = 0usize;

        while pos + DIRENT_HDR_SIZE <= dir_data.len() && count < MAX_DIR_ENTRIES {
            // Each dirent: nid(8) + name_off(2) + file_type(1) + reserved(1) = 12 bytes
            let entry_nid = u64::from_le_bytes([
                dir_data[pos],
                dir_data[pos + 1],
                dir_data[pos + 2],
                dir_data[pos + 3],
                dir_data[pos + 4],
                dir_data[pos + 5],
                dir_data[pos + 6],
                dir_data[pos + 7],
            ]);
            let name_off = u16::from_le_bytes([dir_data[pos + 8], dir_data[pos + 9]]);
            let file_type = dir_data[pos + 10];
            // dir_data[pos + 11] is reserved

            // Determine name length: from name_off to next entry's name_off or block end.
            let next_name_off = if pos + DIRENT_HDR_SIZE + DIRENT_HDR_SIZE <= dir_data.len() {
                u16::from_le_bytes([
                    dir_data[pos + DIRENT_HDR_SIZE + 8],
                    dir_data[pos + DIRENT_HDR_SIZE + 9],
                ]) as usize
            } else {
                dir_size
            };

            let name_start = name_off as usize;
            let name_end = next_name_off.min(dir_size);
            let name_len = if name_end > name_start {
                // Trim trailing nulls.
                let raw = &dir_data[name_start..name_end];
                raw.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1)
            } else {
                0
            }
            .min(MAX_NAME_LEN);

            let mut entry = DirectoryEntry::empty();
            entry.nid = entry_nid;
            entry.name_off = name_off;
            entry.file_type = file_type;
            if name_len > 0 && name_start + name_len <= dir_data.len() {
                entry.name[..name_len]
                    .copy_from_slice(&dir_data[name_start..name_start + name_len]);
                entry.name_len = name_len;
            }

            entries[count] = entry;
            count += 1;
            pos += DIRENT_HDR_SIZE;
        }

        Ok(entries)
    }

    /// Read file data for `nid` into `buf` starting at `offset`.
    ///
    /// Supports `FlatPlain` and `FlatInline` layouts. For `ChunkBased` and
    /// `Compressed` layouts this returns `NotImplemented` (decompression
    /// requires an external compressor service in no_std).
    ///
    /// Returns the number of bytes copied, `NotFound` if `nid` is not a
    /// file, or `IoError` if the image is truncated.
    pub fn read_data(&self, nid: u64, offset: usize, buf: &mut [u8]) -> Result<usize> {
        let inode = self.read_inode(nid)?;
        if !inode.is_file() {
            return Err(Error::NotFound);
        }

        match inode.data_layout {
            DataLayout::FlatPlain => self.read_flat_plain(&inode, offset, buf),
            DataLayout::FlatInline => self.read_flat_inline(&inode, nid, offset, buf),
            DataLayout::ChunkBased | DataLayout::Compressed => Err(Error::NotImplemented),
        }
    }

    /// Read data using the FlatPlain layout.
    fn read_flat_plain(&self, inode: &ErofsInode, offset: usize, buf: &mut [u8]) -> Result<usize> {
        let file_size = inode.size as usize;
        if offset >= file_size {
            return Ok(0);
        }
        let data_start = inode.raw_blkaddr as usize * self.block_size as usize + offset;
        let available = file_size - offset;
        let to_copy = buf.len().min(available);

        if data_start + to_copy > self.data.len() {
            return Err(Error::IoError);
        }

        buf[..to_copy].copy_from_slice(&self.data[data_start..data_start + to_copy]);
        Ok(to_copy)
    }

    /// Read data using the FlatInline layout (tail stored after inode).
    fn read_flat_inline(
        &self,
        inode: &ErofsInode,
        nid: u64,
        offset: usize,
        buf: &mut [u8],
    ) -> Result<usize> {
        let file_size = inode.size as usize;
        if offset >= file_size {
            return Ok(0);
        }

        let block_size = self.block_size as usize;
        let tail_size = file_size % block_size;
        let full_blocks = file_size / block_size;

        // Inline data is stored immediately after the inode in the metadata area.
        let inode_off = self.nid_to_offset(nid);
        let inline_start = inode_off + inode.format.size();

        if offset < full_blocks * block_size {
            // Reading from a full data block.
            let blk = offset / block_size;
            let blk_off = offset % block_size;
            let blk_start = inode.raw_blkaddr as usize * block_size + blk * block_size + blk_off;
            let available = (full_blocks * block_size - offset).min(file_size - offset);
            let to_copy = buf.len().min(available);
            if blk_start + to_copy > self.data.len() {
                return Err(Error::IoError);
            }
            buf[..to_copy].copy_from_slice(&self.data[blk_start..blk_start + to_copy]);
            Ok(to_copy)
        } else {
            // Reading from the inline tail.
            let tail_off = offset - full_blocks * block_size;
            let avail = tail_size.saturating_sub(tail_off);
            let to_copy = buf.len().min(avail);
            let src_start = inline_start + tail_off;
            if to_copy == 0 {
                return Ok(0);
            }
            if src_start + to_copy > self.data.len() {
                return Err(Error::IoError);
            }
            buf[..to_copy].copy_from_slice(&self.data[src_start..src_start + to_copy]);
            Ok(to_copy)
        }
    }

    /// Return a reference to the raw image slice.
    pub fn image(&self) -> &[u8] {
        self.data
    }

    /// Return the block size in bytes.
    pub fn block_size(&self) -> u32 {
        self.block_size
    }
}

impl core::fmt::Debug for ErofsFs<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ErofsFs")
            .field("inos", &self.superblock.inos)
            .field("blocks", &self.superblock.blocks)
            .field("block_size", &self.block_size)
            .field("meta_blkaddr", &self.superblock.meta_blkaddr)
            .finish()
    }
}
