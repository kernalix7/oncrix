// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SquashFS read-only compressed filesystem.
//!
//! SquashFS is a highly compressed, read-only filesystem commonly used in
//! embedded systems and Linux distributions for live media. It stores data
//! in fixed-size blocks and uses metadata compression for efficient access.
//!
//! # Architecture
//!
//! ```text
//! SquashfsSuperblock  (bytes 0..96)
//!   → inode table     (compressed metadata blocks)
//!     → SquashfsInode variants (RegularFile, Directory, Symlink, ...)
//!       → DataBlock list  (compressed/uncompressed data blocks)
//!         → FragmentEntry (tail-end data blocks)
//!   → directory table (compressed directory entries)
//!     → DirectoryEntry  (inode_offset, type, name)
//! ```
//!
//! # Structures
//!
//! - [`CompressionType`] — compression algorithm selector
//! - [`SquashfsSuperblock`] — on-disk superblock (96 bytes)
//! - [`SquashfsInodeType`] — inode type discriminant
//! - [`SquashfsInode`] — per-file metadata variant
//! - [`DirectoryEntry`] — directory listing entry
//! - [`DataBlock`] — data block descriptor (compressed/uncompressed)
//! - [`FragmentEntry`] — fragment table entry for file tails
//! - [`SquashfsFs`] — mounted filesystem handle

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────

/// SquashFS magic number (`sqsh` in little-endian, stored as `hsqs`).
pub const SQUASHFS_MAGIC: u32 = 0x7371_7368;

/// Minimum superblock size in bytes.
const SUPERBLOCK_SIZE: usize = 96;

/// Maximum number of directory entries returned by [`SquashfsFs::readdir`].
const MAX_DIR_ENTRIES: usize = 128;

/// Maximum file name length in a directory entry.
const MAX_NAME_LEN: usize = 256;

/// Maximum fragment entries in the fragment table.
const MAX_FRAGMENT_ENTRIES: usize = 64;

// ── CompressionType ──────────────────────────────────────────────

/// Compression algorithm used for data and metadata blocks.
///
/// SquashFS supports multiple compression algorithms, selected per-filesystem
/// in the superblock. All block-level decompression routes through this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CompressionType {
    /// zlib/DEFLATE compression (id 1).
    Gzip = 1,
    /// LZMA compression (id 2).
    Lzma = 2,
    /// LZO compression (id 3).
    Lzo = 3,
    /// XZ compression (id 4).
    Xz = 4,
    /// LZ4 compression (id 5).
    Lz4 = 5,
    /// Zstandard compression (id 6).
    Zstd = 6,
}

impl CompressionType {
    /// Parse a compression id from its on-disk u16 value.
    ///
    /// Returns `None` for unknown compression ids.
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::Gzip),
            2 => Some(Self::Lzma),
            3 => Some(Self::Lzo),
            4 => Some(Self::Xz),
            5 => Some(Self::Lz4),
            6 => Some(Self::Zstd),
            _ => None,
        }
    }

    /// Return the numeric compression id.
    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

// ── SquashfsSuperblock ───────────────────────────────────────────

/// SquashFS on-disk superblock (96 bytes at offset 0).
///
/// Parsed verbatim from the first 96 bytes of the image. All multi-byte
/// fields are little-endian on disk.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SquashfsSuperblock {
    /// Magic number — must equal [`SQUASHFS_MAGIC`].
    pub magic: u32,
    /// Total inode count.
    pub inode_count: u32,
    /// Filesystem creation timestamp (seconds since epoch).
    pub modification_time: u32,
    /// Uncompressed data block size in bytes (power of two, 4K–1M).
    pub block_size: u32,
    /// Number of fragment blocks.
    pub fragment_count: u32,
    /// Compression algorithm identifier.
    pub compression_id: u16,
    /// Log₂ of block_size (block_size = 1 << block_log).
    pub block_log: u16,
    /// Filesystem flags.
    pub flags: u16,
    /// Number of unique UIDs.
    pub no_ids: u16,
    /// SquashFS version (major).
    pub s_major: u16,
    /// SquashFS version (minor).
    pub s_minor: u16,
    /// Byte offset of the root inode within the inode table.
    pub root_inode: u64,
    /// Total size of the filesystem in bytes.
    pub bytes_used: u64,
    /// Byte offset of the id table.
    pub id_table_start: u64,
    /// Byte offset of the xattr id table.
    pub xattr_id_table_start: u64,
    /// Byte offset of the inode table.
    pub inode_table_start: u64,
    /// Byte offset of the directory table.
    pub directory_table_start: u64,
    /// Byte offset of the fragment table.
    pub fragment_table_start: u64,
    /// Byte offset of the lookup table.
    pub lookup_table_start: u64,
}

impl SquashfsSuperblock {
    /// Parse a superblock from the first 96 bytes of `data`.
    ///
    /// Returns `InvalidArgument` if the buffer is too short, or if the
    /// magic number is wrong or the compression id is unknown.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < SUPERBLOCK_SIZE {
            return Err(Error::InvalidArgument);
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != SQUASHFS_MAGIC {
            return Err(Error::InvalidArgument);
        }

        let inode_count = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let modification_time = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let block_size = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let fragment_count = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let compression_id = u16::from_le_bytes([data[20], data[21]]);
        let block_log = u16::from_le_bytes([data[22], data[23]]);
        let flags = u16::from_le_bytes([data[24], data[25]]);
        let no_ids = u16::from_le_bytes([data[26], data[27]]);
        let s_major = u16::from_le_bytes([data[28], data[29]]);
        let s_minor = u16::from_le_bytes([data[30], data[31]]);
        let root_inode = u64::from_le_bytes([
            data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
        ]);
        let bytes_used = u64::from_le_bytes([
            data[40], data[41], data[42], data[43], data[44], data[45], data[46], data[47],
        ]);
        let id_table_start = u64::from_le_bytes([
            data[48], data[49], data[50], data[51], data[52], data[53], data[54], data[55],
        ]);
        let xattr_id_table_start = u64::from_le_bytes([
            data[56], data[57], data[58], data[59], data[60], data[61], data[62], data[63],
        ]);
        let inode_table_start = u64::from_le_bytes([
            data[64], data[65], data[66], data[67], data[68], data[69], data[70], data[71],
        ]);
        let directory_table_start = u64::from_le_bytes([
            data[72], data[73], data[74], data[75], data[76], data[77], data[78], data[79],
        ]);
        let fragment_table_start = u64::from_le_bytes([
            data[80], data[81], data[82], data[83], data[84], data[85], data[86], data[87],
        ]);
        let lookup_table_start = u64::from_le_bytes([
            data[88], data[89], data[90], data[91], data[92], data[93], data[94], data[95],
        ]);

        // Validate compression id.
        CompressionType::from_u16(compression_id).ok_or(Error::InvalidArgument)?;

        Ok(Self {
            magic,
            inode_count,
            modification_time,
            block_size,
            fragment_count,
            compression_id,
            block_log,
            flags,
            no_ids,
            s_major,
            s_minor,
            root_inode,
            bytes_used,
            id_table_start,
            xattr_id_table_start,
            inode_table_start,
            directory_table_start,
            fragment_table_start,
            lookup_table_start,
        })
    }

    /// Return the compression algorithm in use.
    pub fn compression(&self) -> Option<CompressionType> {
        CompressionType::from_u16(self.compression_id)
    }
}

// ── SquashfsInodeType ────────────────────────────────────────────

/// SquashFS inode type discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SquashfsInodeType {
    /// Regular file (basic, type 1).
    RegularFile = 1,
    /// Directory (basic, type 2).
    Directory = 2,
    /// Symbolic link (basic, type 3).
    Symlink = 3,
    /// Block device (basic, type 4).
    BlockDevice = 4,
    /// Character device (basic, type 5).
    CharDevice = 5,
    /// Named pipe / FIFO (basic, type 6).
    Fifo = 6,
    /// UNIX domain socket (basic, type 7).
    Socket = 7,
    /// Extended regular file (type 8).
    ExtendedRegularFile = 8,
    /// Extended directory (type 9).
    ExtendedDirectory = 9,
}

impl SquashfsInodeType {
    /// Parse an inode type from its on-disk u16 value.
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::RegularFile),
            2 => Some(Self::Directory),
            3 => Some(Self::Symlink),
            4 => Some(Self::BlockDevice),
            5 => Some(Self::CharDevice),
            6 => Some(Self::Fifo),
            7 => Some(Self::Socket),
            8 => Some(Self::ExtendedRegularFile),
            9 => Some(Self::ExtendedDirectory),
            _ => None,
        }
    }
}

// ── SquashfsInode ────────────────────────────────────────────────

/// SquashFS inode — metadata for a single filesystem object.
///
/// The common header fields are present in all inode variants. The
/// variant-specific fields are stored in the `kind` field.
#[derive(Debug, Clone, Copy)]
pub struct SquashfsInode {
    /// Inode type.
    pub inode_type: SquashfsInodeType,
    /// POSIX permission mode bits.
    pub mode: u16,
    /// Owner user id index (into the id table).
    pub uid_idx: u16,
    /// Owner group id index (into the id table).
    pub gid_idx: u16,
    /// Last modification time (seconds since epoch).
    pub mtime: u32,
    /// Inode number.
    pub inode_number: u32,
    /// File size in bytes (0 for non-regular files).
    pub file_size: u64,
    /// Byte offset into the inode table for this inode's data.
    pub inode_table_offset: u64,
    /// Starting block index for data (regular files and directories).
    pub start_block: u32,
    /// Fragment table index (for the last partial block, `u32::MAX` = none).
    pub fragment: u32,
    /// Byte offset within the fragment block.
    pub fragment_offset: u32,
    /// Block offset within the directory table (for directories).
    pub dir_block_start: u32,
    /// Byte offset within the directory table block.
    pub dir_offset: u16,
    /// Number of hard links.
    pub nlink: u32,
}

impl SquashfsInode {
    /// Create a new inode with sensible defaults.
    pub fn new(inode_type: SquashfsInodeType, inode_number: u32) -> Self {
        Self {
            inode_type,
            mode: 0o644,
            uid_idx: 0,
            gid_idx: 0,
            mtime: 0,
            inode_number,
            file_size: 0,
            inode_table_offset: 0,
            start_block: 0,
            fragment: u32::MAX,
            fragment_offset: 0,
            dir_block_start: 0,
            dir_offset: 0,
            nlink: 1,
        }
    }

    /// Whether this inode represents a regular file.
    pub fn is_file(&self) -> bool {
        matches!(
            self.inode_type,
            SquashfsInodeType::RegularFile | SquashfsInodeType::ExtendedRegularFile
        )
    }

    /// Whether this inode represents a directory.
    pub fn is_dir(&self) -> bool {
        matches!(
            self.inode_type,
            SquashfsInodeType::Directory | SquashfsInodeType::ExtendedDirectory
        )
    }

    /// Whether this inode has a fragment tail block.
    pub fn has_fragment(&self) -> bool {
        self.fragment != u32::MAX
    }
}

// ── DirectoryEntry ───────────────────────────────────────────────

/// A single entry within a SquashFS directory block.
///
/// Directory entries are stored in the directory table. The `name`
/// field holds the raw bytes of the filename (not NUL-terminated).
#[derive(Clone, Copy)]
pub struct DirectoryEntry {
    /// Byte offset from the header's `inode_number` base to this inode.
    pub inode_offset: i16,
    /// Inode type for this entry.
    pub inode_type: u16,
    /// Number of bytes in `name` (0-based, actual len = name_size + 1).
    pub name_size: u16,
    /// Filename bytes.
    pub name: [u8; MAX_NAME_LEN],
    /// Actual length of the filename in `name`.
    pub name_len: usize,
}

impl DirectoryEntry {
    /// Create an empty directory entry.
    pub fn empty() -> Self {
        Self {
            inode_offset: 0,
            inode_type: 0,
            name_size: 0,
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
            .field("inode_offset", &self.inode_offset)
            .field("inode_type", &self.inode_type)
            .field("name_len", &self.name_len)
            .finish()
    }
}

// ── DataBlock ────────────────────────────────────────────────────

/// Descriptor for a single SquashFS data block.
///
/// Each data block is either compressed or stored uncompressed. The
/// high bit of `raw_size` indicates compression: if set, the block is
/// uncompressed; otherwise it is compressed with the filesystem's
/// chosen algorithm.
#[derive(Debug, Clone, Copy)]
pub struct DataBlock {
    /// Whether this block is stored uncompressed (high bit of raw_size).
    pub compressed: bool,
    /// Size of the block on-disk in bytes.
    pub size: u32,
    /// Absolute byte offset of the block within the filesystem image.
    pub offset: u64,
}

impl DataBlock {
    /// Parse a data block header from a u32 on-disk value at a given offset.
    pub fn from_raw(raw: u32, offset: u64) -> Self {
        // Bit 24 (SQUASHFS_COMPRESSED_BIT) signals an uncompressed block.
        let compressed = (raw & 0x0100_0000) == 0;
        let size = raw & 0x00FF_FFFF;
        Self {
            compressed,
            size,
            offset,
        }
    }
}

// ── FragmentEntry ────────────────────────────────────────────────

/// Fragment table entry describing a fragment block.
///
/// Fragment blocks hold the tail ends of files whose size is not an
/// exact multiple of the filesystem block size. Multiple file tails
/// may share a single fragment block.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FragmentEntry {
    /// Absolute byte offset of the fragment block within the image.
    pub start_block: u64,
    /// On-disk size of the fragment block (high bit = uncompressed).
    pub size: u32,
    /// Padding / unused field.
    pub unused: u32,
}

impl FragmentEntry {
    /// Create an empty fragment entry.
    pub const fn empty() -> Self {
        Self {
            start_block: 0,
            size: 0,
            unused: 0,
        }
    }

    /// Whether the fragment block is stored uncompressed.
    pub fn is_uncompressed(&self) -> bool {
        (self.size & 0x0100_0000) != 0
    }

    /// Actual on-disk size of the fragment block.
    pub fn disk_size(&self) -> u32 {
        self.size & 0x00FF_FFFF
    }
}

// ── SquashfsFs ───────────────────────────────────────────────────

/// Mounted SquashFS filesystem handle.
///
/// Holds the parsed superblock, table offsets, and a reference to the
/// raw filesystem image. All read operations parse structures directly
/// from the image slice without decompression (stubs in a no_std kernel;
/// actual decompression would require a compressor crate or IPC call).
pub struct SquashfsFs<'a> {
    /// Parsed superblock.
    pub superblock: SquashfsSuperblock,
    /// Byte offset of the inode table.
    pub inode_table_offset: u64,
    /// Byte offset of the directory table.
    pub dir_table_offset: u64,
    /// Byte offset of the fragment table.
    pub fragment_table_offset: u64,
    /// Raw filesystem image.
    data: &'a [u8],
    /// Fragment table entries (parsed at mount time).
    fragments: [FragmentEntry; MAX_FRAGMENT_ENTRIES],
    /// Number of valid fragment entries.
    fragment_count: usize,
}

impl<'a> SquashfsFs<'a> {
    /// Mount a SquashFS filesystem from the given byte slice.
    ///
    /// Parses the superblock, validates the magic and compression id,
    /// and pre-loads the fragment table. Returns `InvalidArgument` if
    /// the image is malformed.
    pub fn mount(data: &'a [u8]) -> Result<Self> {
        let superblock = SquashfsSuperblock::parse(data)?;

        let inode_table_offset = superblock.inode_table_start;
        let dir_table_offset = superblock.directory_table_start;
        let fragment_table_offset = superblock.fragment_table_start;

        let mut fs = Self {
            superblock,
            inode_table_offset,
            dir_table_offset,
            fragment_table_offset,
            data,
            fragments: [FragmentEntry::empty(); MAX_FRAGMENT_ENTRIES],
            fragment_count: 0,
        };

        fs.load_fragment_table()?;
        Ok(fs)
    }

    /// Pre-load fragment table entries from the image.
    fn load_fragment_table(&mut self) -> Result<()> {
        let frag_start = self.fragment_table_offset as usize;
        let frag_count = self.superblock.fragment_count as usize;
        let count = frag_count.min(MAX_FRAGMENT_ENTRIES);

        // Each fragment entry is 16 bytes.
        const ENTRY_SIZE: usize = 16;

        for i in 0..count {
            let off = frag_start + i * ENTRY_SIZE;
            if off + ENTRY_SIZE > self.data.len() {
                break;
            }
            let start_block = u64::from_le_bytes([
                self.data[off],
                self.data[off + 1],
                self.data[off + 2],
                self.data[off + 3],
                self.data[off + 4],
                self.data[off + 5],
                self.data[off + 6],
                self.data[off + 7],
            ]);
            let size = u32::from_le_bytes([
                self.data[off + 8],
                self.data[off + 9],
                self.data[off + 10],
                self.data[off + 11],
            ]);
            let unused = u32::from_le_bytes([
                self.data[off + 12],
                self.data[off + 13],
                self.data[off + 14],
                self.data[off + 15],
            ]);
            self.fragments[i] = FragmentEntry {
                start_block,
                size,
                unused,
            };
            self.fragment_count += 1;
        }
        Ok(())
    }

    /// Read the inode for the given inode number.
    ///
    /// Locates the inode in the inode table and parses its common header.
    /// Returns `NotFound` if the inode number is out of range, or
    /// `IoError` if the image is truncated.
    pub fn read_inode(&self, ino: u64) -> Result<SquashfsInode> {
        if ino == 0 || ino > self.superblock.inode_count as u64 {
            return Err(Error::NotFound);
        }

        // The inode table is a sequence of compressed metadata blocks.
        // In this stub implementation we use the root_inode offset as a
        // base and offset from there. Real decompression is deferred.
        let base = self.inode_table_offset as usize;
        // Inode reference encodes block + offset in the 64-bit root_inode field:
        // upper 32 bits = block index, lower 16 bits = offset within block.
        let block_idx = (self.superblock.root_inode >> 16) as usize;
        let _block_off = (self.superblock.root_inode & 0xFFFF) as usize;

        // Metadata block header (2 bytes): compressed size.
        const META_BLOCK_HDR: usize = 2;
        const META_BLOCK_BODY: usize = 8192; // max uncompressed metadata block size

        let block_start = base + block_idx * (META_BLOCK_HDR + META_BLOCK_BODY);

        // Minimum inode common header is 16 bytes.
        if block_start + 16 > self.data.len() {
            return Err(Error::IoError);
        }

        let d = &self.data[block_start..];
        let inode_type_raw = u16::from_le_bytes([d[0], d[1]]);
        let mode = u16::from_le_bytes([d[2], d[3]]);
        let uid_idx = u16::from_le_bytes([d[4], d[5]]);
        let gid_idx = u16::from_le_bytes([d[6], d[7]]);
        let mtime = u32::from_le_bytes([d[8], d[9], d[10], d[11]]);
        let inode_number = u32::from_le_bytes([d[12], d[13], d[14], d[15]]);

        let inode_type =
            SquashfsInodeType::from_u16(inode_type_raw).ok_or(Error::InvalidArgument)?;

        let mut inode = SquashfsInode::new(inode_type, inode_number);
        inode.mode = mode;
        inode.uid_idx = uid_idx;
        inode.gid_idx = gid_idx;
        inode.mtime = mtime;
        inode.inode_table_offset = block_start as u64;

        // Parse type-specific fields if enough data is present.
        if inode_type == SquashfsInodeType::RegularFile && d.len() >= 32 {
            inode.start_block = u32::from_le_bytes([d[16], d[17], d[18], d[19]]);
            inode.fragment = u32::from_le_bytes([d[20], d[21], d[22], d[23]]);
            inode.fragment_offset = u32::from_le_bytes([d[24], d[25], d[26], d[27]]);
            inode.file_size = u64::from(u32::from_le_bytes([d[28], d[29], d[30], d[31]]));
        } else if inode_type == SquashfsInodeType::Directory && d.len() >= 32 {
            inode.dir_block_start = u32::from_le_bytes([d[16], d[17], d[18], d[19]]);
            inode.nlink = u32::from_le_bytes([d[20], d[21], d[22], d[23]]);
            inode.file_size = u64::from(u16::from_le_bytes([d[24], d[25]]));
            inode.dir_offset = u16::from_le_bytes([d[26], d[27]]);
        }

        Ok(inode)
    }

    /// Read directory entries for the given inode number.
    ///
    /// Returns a fixed-size array slice of up to [`MAX_DIR_ENTRIES`] entries.
    /// Returns `NotFound` if `ino` is not a directory.
    pub fn readdir(&self, ino: u64) -> Result<[DirectoryEntry; MAX_DIR_ENTRIES]> {
        let inode = self.read_inode(ino)?;
        if !inode.is_dir() {
            return Err(Error::NotFound);
        }

        let mut entries = [DirectoryEntry::empty(); MAX_DIR_ENTRIES];

        let dir_table_start = self.dir_table_offset as usize;
        let dir_block = dir_table_start + inode.dir_block_start as usize;
        let dir_off = inode.dir_offset as usize;

        // Directory table block header: 2 bytes (compressed size).
        const DIR_HDR: usize = 2;
        let entry_base = dir_block + DIR_HDR + dir_off;

        // Directory block header (12 bytes): count, inode_number, start.
        if entry_base + 12 > self.data.len() {
            return Ok(entries);
        }

        let d = &self.data[entry_base..];
        let entry_count = u32::from_le_bytes([d[0], d[1], d[2], d[3]]) as usize + 1;
        let _header_inode = u32::from_le_bytes([d[4], d[5], d[6], d[7]]);
        let _start = u32::from_le_bytes([d[8], d[9], d[10], d[11]]);

        let mut pos = 12usize;
        let limit = entry_count.min(MAX_DIR_ENTRIES);
        let mut n = 0usize;

        while n < limit {
            if pos + 8 > d.len() {
                break;
            }
            let inode_offset = i16::from_le_bytes([d[pos], d[pos + 1]]);
            let inode_type = u16::from_le_bytes([d[pos + 2], d[pos + 3]]);
            let name_size = u16::from_le_bytes([d[pos + 4], d[pos + 5]]);
            pos += 8; // skip offset(2), type(2), name_size(2), unused(2)

            let name_len = (name_size as usize) + 1;
            if pos + name_len > d.len() || name_len > MAX_NAME_LEN {
                break;
            }

            let mut entry = DirectoryEntry::empty();
            entry.inode_offset = inode_offset;
            entry.inode_type = inode_type;
            entry.name_size = name_size;
            entry.name[..name_len].copy_from_slice(&d[pos..pos + name_len]);
            entry.name_len = name_len;
            pos += name_len;

            entries[n] = entry;
            n += 1;
        }

        Ok(entries)
    }

    /// Read file data for `ino` into `buf` starting at `offset`.
    ///
    /// Returns the number of bytes copied into `buf`. In a full implementation
    /// each data block would be decompressed before copying. This stub
    /// copies raw block bytes directly, which is correct only for
    /// uncompressed data blocks.
    ///
    /// Returns `NotFound` if `ino` is not a regular file, or `IoError`
    /// if the image is truncated.
    pub fn read_data(&self, ino: u64, offset: usize, buf: &mut [u8]) -> Result<usize> {
        let inode = self.read_inode(ino)?;
        if !inode.is_file() {
            return Err(Error::NotFound);
        }

        let file_size = inode.file_size as usize;
        if offset >= file_size {
            return Ok(0);
        }

        let block_size = self.superblock.block_size as usize;
        let start_block_byte = inode.start_block as usize;

        // Determine which block contains `offset`.
        let block_idx = offset / block_size;
        let block_offset = offset % block_size;

        // Compute on-disk position of the block.
        // Data block headers (4 bytes each) are stored just after the inode.
        // Offset of the first data block header within the inode table:
        let inode_data_hdr = inode.inode_table_offset as usize + 32; // after common + basic hdr
        let hdr_off = inode_data_hdr + block_idx * 4;

        if hdr_off + 4 > self.data.len() {
            return Err(Error::IoError);
        }

        let raw = u32::from_le_bytes([
            self.data[hdr_off],
            self.data[hdr_off + 1],
            self.data[hdr_off + 2],
            self.data[hdr_off + 3],
        ]);

        // Accumulate byte offset to the start of this data block.
        let block_abs = start_block_byte + block_idx * block_size;
        let blk = DataBlock::from_raw(raw, block_abs as u64);

        let blk_start = blk.offset as usize;
        let blk_end = blk_start + blk.size as usize;

        if blk_end > self.data.len() {
            return Err(Error::IoError);
        }

        let src = &self.data[blk_start..blk_end];
        let src_from = block_offset.min(src.len());
        let available = src.len().saturating_sub(src_from);
        let to_copy = buf.len().min(available).min(file_size - offset);

        buf[..to_copy].copy_from_slice(&src[src_from..src_from + to_copy]);
        Ok(to_copy)
    }

    /// Return the fragment entry at the given index.
    ///
    /// Returns `NotFound` if the index is out of range.
    pub fn fragment_entry(&self, idx: usize) -> Result<FragmentEntry> {
        if idx >= self.fragment_count {
            return Err(Error::NotFound);
        }
        Ok(self.fragments[idx])
    }

    /// Return a reference to the raw filesystem image.
    pub fn image(&self) -> &[u8] {
        self.data
    }

    /// Return the total number of fragment entries.
    pub fn fragment_count(&self) -> usize {
        self.fragment_count
    }
}

impl core::fmt::Debug for SquashfsFs<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SquashfsFs")
            .field("inode_count", &self.superblock.inode_count)
            .field("block_size", &self.superblock.block_size)
            .field("compression_id", &self.superblock.compression_id)
            .field("fragment_count", &self.fragment_count)
            .finish()
    }
}
