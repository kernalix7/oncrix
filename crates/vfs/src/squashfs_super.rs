// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SquashFS superblock: on-disk structure and validation.
//!
//! The SquashFS superblock is always at byte offset 0 of the filesystem
//! image. It is exactly 96 bytes in size (for SquashFS 4.0).
//!
//! # Compression types
//!
//! | ID | Algorithm |
//! |----|-----------|
//! | 1 | zlib/DEFLATE |
//! | 2 | lzma |
//! | 3 | lzo |
//! | 4 | xz |
//! | 5 | lz4 |
//! | 6 | zstd |
//!
//! # References
//!
//! - SquashFS 4.0 specification
//! - Linux `fs/squashfs/squashfs_fs.h`
//! - `squashfs-tools` source

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// SquashFS 4.x little-endian magic.
pub const SQUASHFS_MAGIC: u32 = 0x7373_7174; // "tsqs" LE

/// SquashFS 4.x big-endian magic.
pub const SQUASHFS_MAGIC_BE: u32 = 0x7471_7373; // "sqts" BE

/// Superblock offset from start of image (always 0 for SquashFS).
pub const SQUASHFS_SUPER_OFFSET: u64 = 0;

/// On-disk superblock size in bytes.
pub const SQUASHFS_SUPER_SIZE: usize = 96;

/// Minimum block size (4 KiB).
pub const SQUASHFS_MIN_BLOCK_SIZE: u32 = 4096;

/// Maximum block size (1 MiB).
pub const SQUASHFS_MAX_BLOCK_SIZE: u32 = 1 << 20;

/// SquashFS 4.0 version.
pub const SQUASHFS_VERSION: u16 = 4;

/// Compression IDs.
pub const SQFS_COMP_ZLIB: u16 = 1;
/// lzma compression.
pub const SQFS_COMP_LZMA: u16 = 2;
/// lzo compression.
pub const SQFS_COMP_LZO: u16 = 3;
/// xz compression.
pub const SQFS_COMP_XZ: u16 = 4;
/// lz4 compression.
pub const SQFS_COMP_LZ4: u16 = 5;
/// zstd compression.
pub const SQFS_COMP_ZSTD: u16 = 6;

/// Flag: uncompressed inodes.
pub const SQFS_FLAG_UNCOMPRESSED_INODES: u16 = 0x0001;
/// Flag: uncompressed data.
pub const SQFS_FLAG_UNCOMPRESSED_DATA: u16 = 0x0002;
/// Flag: uncompressed fragments.
pub const SQFS_FLAG_UNCOMPRESSED_FRAGS: u16 = 0x0008;
/// Flag: no fragments.
pub const SQFS_FLAG_NO_FRAGS: u16 = 0x0010;
/// Flag: always fragment.
pub const SQFS_FLAG_ALWAYS_FRAGS: u16 = 0x0020;
/// Flag: duplicates.
pub const SQFS_FLAG_DUPLICATES: u16 = 0x0040;
/// Flag: exportable (NFS).
pub const SQFS_FLAG_EXPORTABLE: u16 = 0x0080;
/// Flag: uncompressed xattrs.
pub const SQFS_FLAG_UNCOMPRESSED_XATTRS: u16 = 0x0100;
/// Flag: no xattrs.
pub const SQFS_FLAG_NO_XATTRS: u16 = 0x0200;
/// Flag: has a compressor options block.
pub const SQFS_FLAG_COMP_OPT: u16 = 0x0400;
/// Flag: uncompressed IDs.
pub const SQFS_FLAG_UNCOMPRESSED_IDS: u16 = 0x0800;

// ---------------------------------------------------------------------------
// On-disk superblock (repr(C, packed))
// ---------------------------------------------------------------------------

/// SquashFS 4.0 on-disk superblock.
///
/// All fields are little-endian.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct SquashfsSuperblock {
    /// Magic number (`SQUASHFS_MAGIC`).
    pub s_magic: u32,
    /// Number of inodes.
    pub s_inodes: u32,
    /// Time of last modification (POSIX epoch).
    pub s_mkfs_time: u32,
    /// Uncompressed data block size (must be a power of two, 4 KiB–1 MiB).
    pub s_block_size: u32,
    /// Number of fragment entries.
    pub s_fragments: u32,
    /// Compression algorithm ID.
    pub s_compression: u16,
    /// log2(block_size) − 12.
    pub s_block_log: u16,
    /// Feature flags.
    pub s_flags: u16,
    /// Number of UIDs/GIDs in the ID table.
    pub s_no_ids: u16,
    /// Filesystem version (must be 4).
    pub s_s_major: u16,
    /// Minor version (usually 0).
    pub s_s_minor: u16,
    /// Inode of the root directory.
    pub s_root_inode: u64,
    /// Byte offset to the end of the filesystem image.
    pub s_bytes_used: u64,
    /// Byte offset of the ID table.
    pub s_id_table_start: u64,
    /// Byte offset of the xattr ID table.
    pub s_xattr_id_table_start: u64,
    /// Byte offset of the inode table.
    pub s_inode_table_start: u64,
    /// Byte offset of the directory table.
    pub s_directory_table_start: u64,
    /// Byte offset of the fragment table.
    pub s_fragment_table_start: u64,
    /// Byte offset of the export table (lookup table).
    pub s_lookup_table_start: u64,
}

// ---------------------------------------------------------------------------
// Parsed representation
// ---------------------------------------------------------------------------

/// Validated SquashFS superblock parameters.
#[derive(Clone, Copy, Debug)]
pub struct ParsedSquashfsSuper {
    /// Uncompressed block size in bytes.
    pub block_size: u32,
    /// log2 of block_size.
    pub block_log: u16,
    /// Total number of inodes.
    pub inode_count: u32,
    /// Number of fragment entries.
    pub fragment_count: u32,
    /// Compression algorithm.
    pub compression: u16,
    /// Filesystem feature flags.
    pub flags: u16,
    /// Filesystem version (major).
    pub version_major: u16,
    /// Filesystem version (minor).
    pub version_minor: u16,
    /// Root inode reference.
    pub root_inode: u64,
    /// Total bytes used by the image.
    pub bytes_used: u64,
    /// Offset to inode table.
    pub inode_table_start: u64,
    /// Offset to directory table.
    pub directory_table_start: u64,
    /// Offset to fragment table.
    pub fragment_table_start: u64,
    /// Offset to ID table.
    pub id_table_start: u64,
    /// Offset to export/lookup table.
    pub lookup_table_start: u64,
    /// Whether the image is big-endian.
    pub big_endian: bool,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse the SquashFS superblock from a 96-byte buffer.
///
/// Handles both little-endian and big-endian images.
/// Returns `Err(InvalidArgument)` on magic mismatch or invalid parameters.
pub fn parse_super(buf: &[u8; SQUASHFS_SUPER_SIZE]) -> Result<ParsedSquashfsSuper> {
    let magic_le = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let magic_be = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let big_endian = if magic_le == SQUASHFS_MAGIC {
        false
    } else if magic_be == SQUASHFS_MAGIC_BE {
        true
    } else {
        return Err(Error::InvalidArgument);
    };

    let read_u16 = |off: usize| -> u16 {
        if big_endian {
            u16::from_be_bytes([buf[off], buf[off + 1]])
        } else {
            u16::from_le_bytes([buf[off], buf[off + 1]])
        }
    };
    let read_u32 = |off: usize| -> u32 {
        if big_endian {
            u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
        } else {
            u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
        }
    };
    let read_u64 = |off: usize| -> u64 {
        if big_endian {
            u64::from_be_bytes([
                buf[off],
                buf[off + 1],
                buf[off + 2],
                buf[off + 3],
                buf[off + 4],
                buf[off + 5],
                buf[off + 6],
                buf[off + 7],
            ])
        } else {
            u64::from_le_bytes([
                buf[off],
                buf[off + 1],
                buf[off + 2],
                buf[off + 3],
                buf[off + 4],
                buf[off + 5],
                buf[off + 6],
                buf[off + 7],
            ])
        }
    };

    let inode_count = read_u32(4);
    let block_size = read_u32(12);
    let fragment_count = read_u32(16);
    let compression = read_u16(20);
    let block_log = read_u16(22);
    let flags = read_u16(24);
    let version_major = read_u16(28);
    let version_minor = read_u16(30);
    let root_inode = read_u64(32);
    let bytes_used = read_u64(40);
    let id_table_start = read_u64(48);
    let xattr_id_table_start = read_u64(56);
    let inode_table_start = read_u64(64);
    let directory_table_start = read_u64(72);
    let fragment_table_start = read_u64(80);
    let lookup_table_start = read_u64(88);

    let _ = xattr_id_table_start; // stored but not used in ParsedSquashfsSuper

    Ok(ParsedSquashfsSuper {
        block_size,
        block_log,
        inode_count,
        fragment_count,
        compression,
        flags,
        version_major,
        version_minor,
        root_inode,
        bytes_used,
        inode_table_start,
        directory_table_start,
        fragment_table_start,
        id_table_start,
        lookup_table_start,
        big_endian,
    })
}

/// Validate magic number only (quick pre-check before full parse).
///
/// Returns `Ok(true)` for LE magic, `Ok(false)` for BE magic, `Err` otherwise.
pub fn validate_magic(buf: &[u8]) -> Result<bool> {
    if buf.len() < 4 {
        return Err(Error::InvalidArgument);
    }
    let le = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if le == SQUASHFS_MAGIC {
        return Ok(false); // little-endian
    }
    let be = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if be == SQUASHFS_MAGIC_BE {
        return Ok(true); // big-endian
    }
    Err(Error::InvalidArgument)
}

/// Validate a parsed SquashFS superblock for consistency.
///
/// Returns `Err(InvalidArgument)` if any field is out of range.
pub fn validate_super(sb: &ParsedSquashfsSuper) -> Result<()> {
    if sb.version_major != SQUASHFS_VERSION {
        return Err(Error::InvalidArgument);
    }
    if sb.block_size < SQUASHFS_MIN_BLOCK_SIZE || sb.block_size > SQUASHFS_MAX_BLOCK_SIZE {
        return Err(Error::InvalidArgument);
    }
    if !sb.block_size.is_power_of_two() {
        return Err(Error::InvalidArgument);
    }
    if sb.compression == 0 || sb.compression > SQFS_COMP_ZSTD {
        return Err(Error::InvalidArgument);
    }
    if sb.inode_count == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}
