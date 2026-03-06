// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ext2 superblock: on-disk structure and validation.
//!
//! The ext2 superblock is located at byte offset 1024 from the start of the
//! partition and is 1024 bytes in size. It stores key filesystem parameters
//! that must be read before any inode or block group descriptor can be
//! interpreted.
//!
//! # References
//!
//! - Linux `fs/ext2/ext2.h` (`struct ext2_super_block`)
//! - ext2/3/4 on-disk format documentation
//! - `e2fsprogs` source

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// ext2/3/4 filesystem magic.
pub const EXT2_SUPER_MAGIC: u16 = 0xEF53;

/// Superblock is always at byte offset 1024 from partition start.
pub const SUPERBLOCK_OFFSET: u64 = 1024;

/// Size of the on-disk superblock (padded to 1024 bytes).
pub const SUPERBLOCK_SIZE: usize = 1024;

/// Default block size (1 KiB << `s_log_block_size`).
pub const BASE_BLOCK_SIZE: u64 = 1024;

/// Maximum supported block size (4 KiB for ext2 without large block ext).
pub const MAX_BLOCK_SIZE: u64 = 4096;

/// Root directory inode number.
pub const EXT2_ROOT_INO: u32 = 2;

/// Good filesystem state.
pub const EXT2_VALID_FS: u16 = 1;

/// Filesystem with errors.
pub const EXT2_ERROR_FS: u16 = 2;

/// Feature compat: has extended attributes (`EXT2_FEATURE_COMPAT_EXT_ATTR`).
pub const EXT2_FEATURE_COMPAT_EXT_ATTR: u32 = 0x0008;

/// Feature incompat: uses 64-bit block count (`EXT4_FEATURE_INCOMPAT_64BIT`).
pub const EXT2_FEATURE_INCOMPAT_64BIT: u32 = 0x0080;

// ---------------------------------------------------------------------------
// On-disk superblock (repr(C, packed))
// ---------------------------------------------------------------------------

/// ext2 on-disk superblock.
///
/// Exactly 264 bytes of the most commonly used fields; the remainder of the
/// 1 KiB block is reserved padding (not represented here).
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct Ext2SuperBlock {
    /// Total inode count.
    pub s_inodes_count: u32,
    /// Total block count (low 32 bits).
    pub s_blocks_count: u32,
    /// Blocks reserved for super-user.
    pub s_r_blocks_count: u32,
    /// Free block count.
    pub s_free_blocks_count: u32,
    /// Free inode count.
    pub s_free_inodes_count: u32,
    /// First data block (block containing the superblock).
    pub s_first_data_block: u32,
    /// Block size = 1024 << `s_log_block_size`.
    pub s_log_block_size: u32,
    /// Fragment size = 1024 << `s_log_frag_size` (ignored in ext4).
    pub s_log_frag_size: u32,
    /// Blocks per block group.
    pub s_blocks_per_group: u32,
    /// Fragments per block group.
    pub s_frags_per_group: u32,
    /// Inodes per block group.
    pub s_inodes_per_group: u32,
    /// Last mount time (POSIX epoch seconds).
    pub s_mtime: u32,
    /// Last write time.
    pub s_wtime: u32,
    /// Mount count since last fsck.
    pub s_mnt_count: u16,
    /// Maximum mount count before fsck.
    pub s_max_mnt_count: u16,
    /// Filesystem magic number (must be `EXT2_SUPER_MAGIC`).
    pub s_magic: u16,
    /// Filesystem state (`EXT2_VALID_FS` or `EXT2_ERROR_FS`).
    pub s_state: u16,
    /// Behaviour on error: 1=continue, 2=remount ro, 3=panic.
    pub s_errors: u16,
    /// Minor revision level.
    pub s_minor_rev_level: u16,
    /// Last fsck time.
    pub s_lastcheck: u32,
    /// Maximum interval between fscks.
    pub s_checkinterval: u32,
    /// Creator OS.
    pub s_creator_os: u32,
    /// Revision level.
    pub s_rev_level: u32,
    /// UID reserved for root blocks.
    pub s_def_resuid: u16,
    /// GID reserved for root blocks.
    pub s_def_resgid: u16,
    // ── Rev 1 fields ────────────────────────────────────────────────
    /// First non-reserved inode.
    pub s_first_ino: u32,
    /// Size of each inode (128 for ext2, 256 for ext4).
    pub s_inode_size: u16,
    /// Block group containing this superblock.
    pub s_block_group_nr: u16,
    /// Compatible feature set flags.
    pub s_feature_compat: u32,
    /// Incompatible feature set flags.
    pub s_feature_incompat: u32,
    /// Read-only compatible feature set flags.
    pub s_feature_ro_compat: u32,
    /// 128-bit UUID for the filesystem.
    pub s_uuid: [u8; 16],
    /// Volume label (NUL-terminated string).
    pub s_volume_name: [u8; 16],
    /// Last mounted directory.
    pub s_last_mounted: [u8; 64],
    /// Compression algorithms used.
    pub s_algorithm_usage_bitmap: u32,
}

// ---------------------------------------------------------------------------
// Parsed superblock
// ---------------------------------------------------------------------------

/// Parsed and validated ext2 superblock parameters.
#[derive(Clone, Copy, Debug)]
pub struct ParsedSuper {
    /// Block size in bytes.
    pub block_size: u64,
    /// Total number of blocks.
    pub block_count: u64,
    /// Total number of inodes.
    pub inode_count: u32,
    /// Blocks per block group.
    pub blocks_per_group: u32,
    /// Inodes per block group.
    pub inodes_per_group: u32,
    /// Number of block groups.
    pub group_count: u32,
    /// Inode size in bytes.
    pub inode_size: u16,
    /// First inode usable by regular files.
    pub first_ino: u32,
    /// Filesystem UUID.
    pub uuid: [u8; 16],
    /// Compatible features.
    pub feature_compat: u32,
    /// Incompatible features.
    pub feature_incompat: u32,
    /// Read-only compatible features.
    pub feature_ro_compat: u32,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse the on-disk superblock from a raw 1024-byte buffer.
///
/// Returns `Err(InvalidArgument)` if the magic number is wrong or the
/// block size is out of range.
pub fn parse_super(buf: &[u8; SUPERBLOCK_SIZE]) -> Result<ParsedSuper> {
    // Read magic at offset 56 (little-endian u16).
    let magic = u16::from_le_bytes([buf[56], buf[57]]);
    if magic != EXT2_SUPER_MAGIC {
        return Err(Error::InvalidArgument);
    }
    let log_block_size = u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]);
    let block_size = BASE_BLOCK_SIZE << log_block_size;
    if block_size > MAX_BLOCK_SIZE {
        return Err(Error::InvalidArgument);
    }

    let inode_count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let blocks_count_lo = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let blocks_per_group = u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]);
    let inodes_per_group = u32::from_le_bytes([buf[40], buf[41], buf[42], buf[43]]);

    if blocks_per_group == 0 || inodes_per_group == 0 {
        return Err(Error::InvalidArgument);
    }
    let group_count = (blocks_count_lo + blocks_per_group - 1) / blocks_per_group;

    let inode_size = u16::from_le_bytes([buf[88], buf[89]]);
    let inode_size = if inode_size == 0 { 128 } else { inode_size };
    let first_ino = u32::from_le_bytes([buf[84], buf[85], buf[86], buf[87]]);
    let first_ino = if first_ino == 0 { 11 } else { first_ino };

    let feature_compat = u32::from_le_bytes([buf[92], buf[93], buf[94], buf[95]]);
    let feature_incompat = u32::from_le_bytes([buf[96], buf[97], buf[98], buf[99]]);
    let feature_ro_compat = u32::from_le_bytes([buf[100], buf[101], buf[102], buf[103]]);

    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&buf[104..120]);

    Ok(ParsedSuper {
        block_size,
        block_count: blocks_count_lo as u64,
        inode_count,
        blocks_per_group,
        inodes_per_group,
        group_count,
        inode_size,
        first_ino,
        uuid,
        feature_compat,
        feature_incompat,
        feature_ro_compat,
    })
}

/// Validate a previously parsed superblock for basic consistency.
///
/// Returns `Err(InvalidArgument)` if any constraint is violated.
pub fn validate_super(sb: &ParsedSuper) -> Result<()> {
    if sb.block_size == 0 || sb.block_size > MAX_BLOCK_SIZE {
        return Err(Error::InvalidArgument);
    }
    if sb.inode_count == 0 {
        return Err(Error::InvalidArgument);
    }
    if sb.blocks_per_group == 0 || sb.inodes_per_group == 0 {
        return Err(Error::InvalidArgument);
    }
    if sb.group_count == 0 {
        return Err(Error::InvalidArgument);
    }
    if sb.inode_size < 128 || sb.inode_size > 1024 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Encode a `ParsedSuper` back into the raw 1024-byte buffer for writing.
///
/// Only the fields that `parse_super` reads are updated; other fields are
/// left unchanged.
pub fn update_super(sb: &ParsedSuper, buf: &mut [u8; SUPERBLOCK_SIZE]) -> Result<()> {
    validate_super(sb)?;

    // Blocks count (low 32 bits at offset 4).
    let bc = sb.block_count as u32;
    buf[4..8].copy_from_slice(&bc.to_le_bytes());

    // log_block_size at offset 24.
    let log = match sb.block_size {
        1024 => 0u32,
        2048 => 1,
        4096 => 2,
        _ => return Err(Error::InvalidArgument),
    };
    buf[24..28].copy_from_slice(&log.to_le_bytes());

    // blocks_per_group at 32, inodes_per_group at 40.
    buf[32..36].copy_from_slice(&sb.blocks_per_group.to_le_bytes());
    buf[40..44].copy_from_slice(&sb.inodes_per_group.to_le_bytes());

    // inode_size at 88.
    buf[88..90].copy_from_slice(&sb.inode_size.to_le_bytes());

    // first_ino at 84.
    buf[84..88].copy_from_slice(&sb.first_ino.to_le_bytes());

    // feature flags at 92/96/100.
    buf[92..96].copy_from_slice(&sb.feature_compat.to_le_bytes());
    buf[96..100].copy_from_slice(&sb.feature_incompat.to_le_bytes());
    buf[100..104].copy_from_slice(&sb.feature_ro_compat.to_le_bytes());

    // UUID at 104.
    buf[104..120].copy_from_slice(&sb.uuid);

    // Re-write magic.
    buf[56..58].copy_from_slice(&EXT2_SUPER_MAGIC.to_le_bytes());

    Ok(())
}

/// Compute the block number of the block group descriptor table.
///
/// The GDT immediately follows the superblock's block. When the block size
/// is 1 KiB the superblock occupies block 1, so the GDT starts at block 2.
pub fn gdt_start_block(sb: &ParsedSuper) -> u64 {
    if sb.block_size == 1024 { 2 } else { 1 }
}
