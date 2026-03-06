// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Universal Disk Format (UDF) filesystem — ECMA-167 / ISO 13346.
//!
//! UDF is the standard filesystem for DVD, Blu-ray, and modern optical
//! media. It supersedes ISO 9660 for writable media and provides full
//! POSIX semantics including long filenames, permissions, and timestamps.
//!
//! # On-disk layout
//!
//! ```text
//! Sector 256  -- Anchor Volume Descriptor Pointer (AVDP)
//! MVDS area   -- Main Volume Descriptor Sequence
//!   - Primary Volume Descriptor (PVD, tag 1)
//!   - Logical Volume Descriptor (LVD, tag 6)
//!   - Partition Descriptor (PD, tag 5)
//! Partition    -- File data and metadata
//!   - File Set Descriptor (FSD, tag 256)
//!     - Root ICB  -> File Entry (tag 261/266)
//!       - Allocation Descriptors (short/long/extended)
//! ```
//!
//! # Supported UDF revisions
//!
//! - UDF 1.50 (DVD-R/RW)
//! - UDF 2.00 (DVD-R DL)
//! - UDF 2.01 (most common for DVD media)
//! - UDF 2.50 (Blu-ray)
//! - UDF 2.60 (Blu-ray rewritable)
//!
//! # Structures
//!
//! - [`AnchorVolumeDescriptor`] — AVDP at sector 256
//! - [`UdfPartitionDescriptor`] — partition location and size
//! - [`LogicalVolumeDescriptor`] — logical volume metadata
//! - [`IcbTag`] — Information Control Block tag
//! - [`FileEntry`] — standard file entry (tag 261)
//! - [`ExtendedFileEntry`] — extended file entry (tag 266)
//! - [`ShortAlloc`] / [`LongAlloc`] / [`ExtendedAlloc`]
//! - [`FileIdentifier`] — directory entry
//! - [`UdfFs`] — mounted filesystem handle
//!
//! # References
//!
//! - ECMA-167 4th edition (Volume and File Structure)
//! - UDF 2.60 specification (OSTA)
//! - Linux kernel `fs/udf/`

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────

/// UDF sector size (2048 bytes, same as CD-ROM).
pub const UDF_SECTOR_SIZE: usize = 2048;

/// Sector number of the first Anchor Volume Descriptor Pointer.
const AVDP_SECTOR: usize = 256;

/// ECMA-167 descriptor tag identifiers.
const TAG_PRIMARY_VD: u16 = 1;
const TAG_ANCHOR_VDP: u16 = 2;
const TAG_PARTITION_DESC: u16 = 5;
const TAG_LOGICAL_VD: u16 = 6;
const TAG_FILE_SET_DESC: u16 = 256;
const TAG_FILE_ENTRY: u16 = 261;
const TAG_EXTENDED_FILE_ENTRY: u16 = 266;
const TAG_FILE_IDENTIFIER: u16 = 257;

/// Maximum directory entries returned by readdir.
const MAX_DIR_ENTRIES: usize = 128;

/// Maximum filename length in bytes.
const MAX_NAME_LEN: usize = 255;

/// Maximum number of allocation descriptors per file entry.
const MAX_ALLOC_DESCS: usize = 64;

/// ICB file type: directory.
const ICB_FILE_TYPE_DIRECTORY: u8 = 4;

/// ICB file type: regular file.
const ICB_FILE_TYPE_REGULAR: u8 = 5;

/// ICB file type: symbolic link.
const ICB_FILE_TYPE_SYMLINK: u8 = 12;

/// Allocation descriptor type field values (bits 0-2 of flags in ICB tag).
const ALLOC_TYPE_SHORT: u16 = 0;
const ALLOC_TYPE_LONG: u16 = 1;
const ALLOC_TYPE_EXTENDED: u16 = 2;
const ALLOC_TYPE_EMBEDDED: u16 = 3;

// ── Descriptor Tag ───────────────────────────────────────────────

/// ECMA-167 descriptor tag (16 bytes at the start of every descriptor).
///
/// Used to identify and validate on-disk structures.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct DescriptorTag {
    /// Tag identifier (determines the descriptor type).
    pub tag_id: u16,
    /// Descriptor version.
    pub descriptor_version: u16,
    /// Tag checksum (8-bit sum of bytes 0..15, excluding byte 4).
    pub tag_checksum: u8,
    /// Tag serial number.
    pub tag_serial: u16,
    /// CRC of descriptor body.
    pub descriptor_crc: u16,
    /// Length of CRC-covered area.
    pub descriptor_crc_len: u16,
    /// Sector location of this tag.
    pub tag_location: u32,
}

impl DescriptorTag {
    /// Parse a descriptor tag from the first 16 bytes of `data`.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 16 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            tag_id: read_u16_le(&data[0..2]),
            descriptor_version: read_u16_le(&data[2..4]),
            tag_checksum: data[4],
            tag_serial: read_u16_le(&data[6..8]),
            descriptor_crc: read_u16_le(&data[8..10]),
            descriptor_crc_len: read_u16_le(&data[10..12]),
            tag_location: read_u32_le(&data[12..16]),
        })
    }

    /// Verify the tag checksum (sum of bytes 0..15 excluding byte 4).
    pub fn verify_checksum(&self, raw: &[u8]) -> bool {
        if raw.len() < 16 {
            return false;
        }
        let mut sum: u8 = 0;
        for i in 0..16 {
            if i != 4 {
                sum = sum.wrapping_add(raw[i]);
            }
        }
        sum == self.tag_checksum
    }
}

// ── AnchorVolumeDescriptor ───────────────────────────────────────

/// Anchor Volume Descriptor Pointer (AVDP), found at sector 256.
///
/// Points to the Main Volume Descriptor Sequence (MVDS) and the
/// Reserve Volume Descriptor Sequence (RVDS).
#[derive(Debug, Clone, Copy)]
pub struct AnchorVolumeDescriptor {
    /// Tag (must have tag_id == 2).
    pub tag: DescriptorTag,
    /// Extent of the Main Volume Descriptor Sequence.
    pub mvds_location: u32,
    /// Length of the MVDS in bytes.
    pub mvds_length: u32,
    /// Extent of the Reserve Volume Descriptor Sequence.
    pub rvds_location: u32,
    /// Length of the RVDS in bytes.
    pub rvds_length: u32,
}

impl AnchorVolumeDescriptor {
    /// Parse an AVDP from a sector buffer.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 512 {
            return Err(Error::InvalidArgument);
        }
        let tag = DescriptorTag::parse(data)?;
        if tag.tag_id != TAG_ANCHOR_VDP {
            return Err(Error::InvalidArgument);
        }

        Ok(Self {
            tag,
            mvds_location: read_u32_le(&data[16..20]),
            mvds_length: read_u32_le(&data[20..24]),
            rvds_location: read_u32_le(&data[24..28]),
            rvds_length: read_u32_le(&data[28..32]),
        })
    }
}

// ── UdfPartitionDescriptor ───────────────────────────────────────

/// UDF Partition Descriptor (tag 5).
///
/// Describes a single partition on the media, including its starting
/// sector and length.
#[derive(Debug, Clone, Copy)]
pub struct UdfPartitionDescriptor {
    /// Descriptor tag.
    pub tag: DescriptorTag,
    /// Volume descriptor sequence number.
    pub vds_number: u32,
    /// Partition flags.
    pub partition_flags: u16,
    /// Partition number.
    pub partition_number: u16,
    /// Starting sector of the partition.
    pub partition_start: u32,
    /// Length of the partition in sectors.
    pub partition_length: u32,
    /// Access type (1=read-only, 2=write-once, 3=rewritable, 4=overwritable).
    pub access_type: u32,
}

impl UdfPartitionDescriptor {
    /// Parse a partition descriptor from sector data.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 512 {
            return Err(Error::InvalidArgument);
        }
        let tag = DescriptorTag::parse(data)?;
        if tag.tag_id != TAG_PARTITION_DESC {
            return Err(Error::InvalidArgument);
        }

        Ok(Self {
            tag,
            vds_number: read_u32_le(&data[16..20]),
            partition_flags: read_u16_le(&data[20..22]),
            partition_number: read_u16_le(&data[22..24]),
            // Partition contents at 24..56 (Entity Identifier, skip).
            partition_start: read_u32_le(&data[188..192]),
            partition_length: read_u32_le(&data[192..196]),
            access_type: read_u32_le(&data[184..188]),
        })
    }

    /// Returns `true` if this partition is read-only.
    pub fn is_read_only(&self) -> bool {
        self.access_type == 1
    }
}

// ── LogicalVolumeDescriptor ──────────────────────────────────────

/// UDF Logical Volume Descriptor (tag 6).
///
/// Maps logical block addresses to physical partitions and contains
/// the logical volume name and block size.
#[derive(Debug, Clone, Copy)]
pub struct LogicalVolumeDescriptor {
    /// Descriptor tag.
    pub tag: DescriptorTag,
    /// Volume descriptor sequence number.
    pub vds_number: u32,
    /// Logical volume identifier (128 bytes, d-string).
    pub lv_identifier: [u8; 128],
    /// Logical block size in bytes.
    pub logical_block_size: u32,
    /// FSD extent location (logical block number).
    pub fsd_location: u32,
    /// FSD extent length.
    pub fsd_length: u32,
}

impl LogicalVolumeDescriptor {
    /// Parse a logical volume descriptor from sector data.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 512 {
            return Err(Error::InvalidArgument);
        }
        let tag = DescriptorTag::parse(data)?;
        if tag.tag_id != TAG_LOGICAL_VD {
            return Err(Error::InvalidArgument);
        }

        let vds_number = read_u32_le(&data[16..20]);
        let mut lv_identifier = [0u8; 128];
        lv_identifier.copy_from_slice(&data[84..212]);
        let logical_block_size = read_u32_le(&data[212..216]);

        // Logical Volume Contents Use at offset 248..280 contains
        // the FSD extent (long allocation descriptor).
        let fsd_length = read_u32_le(&data[248..252]);
        let fsd_location = read_u32_le(&data[252..256]);

        Ok(Self {
            tag,
            vds_number,
            lv_identifier,
            logical_block_size,
            fsd_location,
            fsd_length,
        })
    }

    /// Returns the volume name as a trimmed byte slice.
    pub fn volume_name(&self) -> &[u8] {
        // d-string: first byte is compression id, rest is the name.
        // Trim trailing zeros and spaces.
        let mut end = 128;
        while end > 1 && (self.lv_identifier[end - 1] == 0 || self.lv_identifier[end - 1] == b' ') {
            end -= 1;
        }
        if end > 1 {
            &self.lv_identifier[1..end]
        } else {
            &self.lv_identifier[..0]
        }
    }
}

// ── IcbTag ───────────────────────────────────────────────────────

/// Information Control Block (ICB) tag — 20 bytes.
///
/// Embedded in every File Entry and Extended File Entry. Identifies the
/// file type, allocation descriptor format, and strategy type.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct IcbTag {
    /// Prior recorded number of direct entries.
    pub prior_direct_entries: u32,
    /// ICB strategy type (4 = normal).
    pub strategy_type: u16,
    /// Strategy parameter.
    pub strategy_param: u16,
    /// Maximum number of entries.
    pub max_entries: u16,
    /// File type (4=directory, 5=regular, 12=symlink, etc.).
    pub file_type: u8,
    /// Parent ICB location (logical block).
    pub parent_icb_location: u32,
    /// Parent ICB partition reference.
    pub parent_icb_partition: u16,
    /// Flags (bits 0-2: allocation descriptor type).
    pub flags: u16,
}

impl IcbTag {
    /// Parse an ICB tag from 20 bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 20 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            prior_direct_entries: read_u32_le(&data[0..4]),
            strategy_type: read_u16_le(&data[4..6]),
            strategy_param: read_u16_le(&data[6..8]),
            max_entries: read_u16_le(&data[8..10]),
            file_type: data[11],
            parent_icb_location: read_u32_le(&data[12..16]),
            parent_icb_partition: read_u16_le(&data[16..18]),
            flags: read_u16_le(&data[18..20]),
        })
    }

    /// Returns the allocation descriptor type from the flags field.
    pub fn alloc_type(&self) -> u16 {
        self.flags & 0x07
    }

    /// Returns `true` if this ICB represents a directory.
    pub fn is_directory(&self) -> bool {
        self.file_type == ICB_FILE_TYPE_DIRECTORY
    }

    /// Returns `true` if this ICB represents a regular file.
    pub fn is_regular_file(&self) -> bool {
        self.file_type == ICB_FILE_TYPE_REGULAR
    }

    /// Returns `true` if this ICB represents a symbolic link.
    pub fn is_symlink(&self) -> bool {
        self.file_type == ICB_FILE_TYPE_SYMLINK
    }
}

// ── Allocation Descriptors ───────────────────────────────────────

/// Short Allocation Descriptor (8 bytes).
///
/// Used when all extents lie within the same partition.
#[derive(Debug, Clone, Copy)]
pub struct ShortAlloc {
    /// Extent length in bytes (upper 2 bits: type, lower 30 bits: length).
    pub extent_length: u32,
    /// Extent position (logical block number within partition).
    pub extent_position: u32,
}

impl ShortAlloc {
    /// Parse a short allocation descriptor from 8 bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            extent_length: read_u32_le(&data[0..4]),
            extent_position: read_u32_le(&data[4..8]),
        })
    }

    /// Returns the actual extent length (lower 30 bits).
    pub fn length(&self) -> u32 {
        self.extent_length & 0x3FFF_FFFF
    }

    /// Returns the extent type (upper 2 bits).
    pub fn extent_type(&self) -> u8 {
        (self.extent_length >> 30) as u8
    }

    /// Returns `true` if this is an allocated and recorded extent.
    pub fn is_recorded(&self) -> bool {
        self.extent_type() == 0
    }
}

/// Long Allocation Descriptor (16 bytes).
///
/// Used when extents may span multiple partitions.
#[derive(Debug, Clone, Copy)]
pub struct LongAlloc {
    /// Extent length in bytes (upper 2 bits: type).
    pub extent_length: u32,
    /// Extent location (logical block number).
    pub extent_location: u32,
    /// Partition reference number.
    pub partition_ref: u16,
    /// Implementation use (6 bytes).
    pub impl_use: [u8; 6],
}

impl LongAlloc {
    /// Parse a long allocation descriptor from 16 bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 16 {
            return Err(Error::InvalidArgument);
        }
        let mut impl_use = [0u8; 6];
        impl_use.copy_from_slice(&data[10..16]);
        Ok(Self {
            extent_length: read_u32_le(&data[0..4]),
            extent_location: read_u32_le(&data[4..8]),
            partition_ref: read_u16_le(&data[8..10]),
            impl_use,
        })
    }

    /// Returns the actual extent length (lower 30 bits).
    pub fn length(&self) -> u32 {
        self.extent_length & 0x3FFF_FFFF
    }

    /// Returns the extent type (upper 2 bits).
    pub fn extent_type(&self) -> u8 {
        (self.extent_length >> 30) as u8
    }
}

/// Extended Allocation Descriptor (20 bytes).
///
/// Adds an information length field for advanced allocation strategies.
#[derive(Debug, Clone, Copy)]
pub struct ExtendedAlloc {
    /// Extent length in bytes.
    pub extent_length: u32,
    /// Recorded length of information in the extent.
    pub recorded_length: u32,
    /// Information length (logical).
    pub information_length: u32,
    /// Extent location (logical block number).
    pub extent_location: u32,
    /// Partition reference number.
    pub partition_ref: u16,
    /// Implementation use (2 bytes).
    pub impl_use: [u8; 2],
}

impl ExtendedAlloc {
    /// Parse an extended allocation descriptor from 20 bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 20 {
            return Err(Error::InvalidArgument);
        }
        let mut impl_use = [0u8; 2];
        impl_use.copy_from_slice(&data[18..20]);
        Ok(Self {
            extent_length: read_u32_le(&data[0..4]),
            recorded_length: read_u32_le(&data[4..8]),
            information_length: read_u32_le(&data[8..12]),
            extent_location: read_u32_le(&data[12..16]),
            partition_ref: read_u16_le(&data[16..18]),
            impl_use,
        })
    }

    /// Returns the actual extent length (lower 30 bits).
    pub fn length(&self) -> u32 {
        self.extent_length & 0x3FFF_FFFF
    }
}

// ── FileEntry ────────────────────────────────────────────────────

/// UDF File Entry (tag 261) — standard file metadata.
///
/// Contains the ICB tag, timestamps, permissions, file size, and
/// allocation descriptors for a single file or directory.
#[derive(Debug, Clone, Copy)]
pub struct FileEntry {
    /// Descriptor tag.
    pub tag: DescriptorTag,
    /// ICB tag (file type, alloc strategy).
    pub icb_tag: IcbTag,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Permissions (UDF-style, not POSIX directly).
    pub permissions: u32,
    /// Number of hard links.
    pub link_count: u16,
    /// File size in bytes (information length).
    pub information_length: u64,
    /// Number of bytes allocated on disk (logical blocks allocated).
    pub logical_blocks_recorded: u64,
    /// Length of allocation descriptors in bytes.
    pub alloc_descs_length: u32,
    /// Offset where allocation descriptors begin in the raw entry.
    pub alloc_descs_offset: usize,
}

impl FileEntry {
    /// Parse a File Entry from sector data.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 176 {
            return Err(Error::InvalidArgument);
        }
        let tag = DescriptorTag::parse(data)?;
        if tag.tag_id != TAG_FILE_ENTRY {
            return Err(Error::InvalidArgument);
        }

        let icb_tag = IcbTag::parse(&data[16..36])?;
        let uid = read_u32_le(&data[36..40]);
        let gid = read_u32_le(&data[40..44]);
        let permissions = read_u32_le(&data[44..48]);
        let link_count = read_u16_le(&data[48..50]);
        let information_length = read_u64_le(&data[56..64]);
        let logical_blocks_recorded = read_u64_le(&data[64..72]);

        // Extended attribute length at offset 168.
        let ea_length = read_u32_le(&data[168..172]) as usize;
        let alloc_descs_length = read_u32_le(&data[172..176]);
        let alloc_descs_offset = 176 + ea_length;

        Ok(Self {
            tag,
            icb_tag,
            uid,
            gid,
            permissions,
            link_count,
            information_length,
            logical_blocks_recorded,
            alloc_descs_length,
            alloc_descs_offset,
        })
    }

    /// Parse short allocation descriptors from the raw entry data.
    pub fn parse_short_allocs(&self, data: &[u8]) -> ([ShortAlloc; MAX_ALLOC_DESCS], usize) {
        let mut allocs = [ShortAlloc {
            extent_length: 0,
            extent_position: 0,
        }; MAX_ALLOC_DESCS];
        let mut count = 0;
        let start = self.alloc_descs_offset;
        let end = start + self.alloc_descs_length as usize;

        let mut pos = start;
        while pos + 8 <= end && pos + 8 <= data.len() && count < MAX_ALLOC_DESCS {
            if let Ok(ad) = ShortAlloc::parse(&data[pos..]) {
                if ad.length() == 0 {
                    break;
                }
                allocs[count] = ad;
                count += 1;
            }
            pos += 8;
        }

        (allocs, count)
    }

    /// Parse long allocation descriptors from the raw entry data.
    pub fn parse_long_allocs(&self, data: &[u8]) -> ([LongAlloc; MAX_ALLOC_DESCS], usize) {
        let mut allocs = [LongAlloc {
            extent_length: 0,
            extent_location: 0,
            partition_ref: 0,
            impl_use: [0u8; 6],
        }; MAX_ALLOC_DESCS];
        let mut count = 0;
        let start = self.alloc_descs_offset;
        let end = start + self.alloc_descs_length as usize;

        let mut pos = start;
        while pos + 16 <= end && pos + 16 <= data.len() && count < MAX_ALLOC_DESCS {
            if let Ok(ad) = LongAlloc::parse(&data[pos..]) {
                if ad.length() == 0 {
                    break;
                }
                allocs[count] = ad;
                count += 1;
            }
            pos += 16;
        }

        (allocs, count)
    }

    /// Convert UDF permissions to approximate POSIX mode bits.
    pub fn posix_mode(&self) -> u16 {
        // UDF permissions: bits 0-4 = other, 5-9 = group, 10-14 = owner
        // Each group has: read(0), write(1), execute(2), chattr(3), delete(4)
        let other = (self.permissions & 0x1F) as u16;
        let group = ((self.permissions >> 5) & 0x1F) as u16;
        let owner = ((self.permissions >> 10) & 0x1F) as u16;

        let to_rwx = |p: u16| -> u16 {
            let r = if p & 0x01 != 0 { 4 } else { 0 };
            let w = if p & 0x02 != 0 { 2 } else { 0 };
            let x = if p & 0x04 != 0 { 1 } else { 0 };
            r | w | x
        };

        (to_rwx(owner) << 6) | (to_rwx(group) << 3) | to_rwx(other)
    }
}

// ── ExtendedFileEntry ────────────────────────────────────────────

/// UDF Extended File Entry (tag 266).
///
/// Extends [`FileEntry`] with creation timestamp and object size
/// fields. Used in UDF 2.00+ revisions.
#[derive(Debug, Clone, Copy)]
pub struct ExtendedFileEntry {
    /// Descriptor tag.
    pub tag: DescriptorTag,
    /// ICB tag.
    pub icb_tag: IcbTag,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Permissions.
    pub permissions: u32,
    /// Number of hard links.
    pub link_count: u16,
    /// Information length (file size in bytes).
    pub information_length: u64,
    /// Object size (for streams).
    pub object_size: u64,
    /// Logical blocks recorded.
    pub logical_blocks_recorded: u64,
    /// Allocation descriptors length.
    pub alloc_descs_length: u32,
    /// Offset of allocation descriptors in raw data.
    pub alloc_descs_offset: usize,
}

impl ExtendedFileEntry {
    /// Parse an Extended File Entry from sector data.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 216 {
            return Err(Error::InvalidArgument);
        }
        let tag = DescriptorTag::parse(data)?;
        if tag.tag_id != TAG_EXTENDED_FILE_ENTRY {
            return Err(Error::InvalidArgument);
        }

        let icb_tag = IcbTag::parse(&data[16..36])?;
        let uid = read_u32_le(&data[36..40]);
        let gid = read_u32_le(&data[40..44]);
        let permissions = read_u32_le(&data[44..48]);
        let link_count = read_u16_le(&data[48..50]);
        let information_length = read_u64_le(&data[56..64]);
        let object_size = read_u64_le(&data[64..72]);
        let logical_blocks_recorded = read_u64_le(&data[72..80]);

        let ea_length = read_u32_le(&data[208..212]) as usize;
        let alloc_descs_length = read_u32_le(&data[212..216]);
        let alloc_descs_offset = 216 + ea_length;

        Ok(Self {
            tag,
            icb_tag,
            uid,
            gid,
            permissions,
            link_count,
            information_length,
            object_size,
            logical_blocks_recorded,
            alloc_descs_length,
            alloc_descs_offset,
        })
    }
}

// ── FileIdentifier ───────────────────────────────────────────────

/// UDF File Identifier Descriptor (tag 257) — directory entry.
///
/// Each entry in a directory maps a filename to an ICB location.
#[derive(Clone, Copy)]
pub struct FileIdentifier {
    /// Descriptor tag.
    pub tag_id: u16,
    /// File version number.
    pub file_version: u16,
    /// File characteristics (bit 1 = directory, bit 2 = deleted, bit 3 = parent).
    pub file_characteristics: u8,
    /// ICB location (logical block number).
    pub icb_location: u32,
    /// ICB partition reference.
    pub icb_partition: u16,
    /// File identifier (name) bytes.
    pub name: [u8; MAX_NAME_LEN],
    /// Actual name length.
    pub name_len: usize,
    /// Total record length on disk.
    pub record_len: usize,
}

impl FileIdentifier {
    /// Creates an empty file identifier.
    pub fn empty() -> Self {
        Self {
            tag_id: 0,
            file_version: 0,
            file_characteristics: 0,
            icb_location: 0,
            icb_partition: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            record_len: 0,
        }
    }

    /// Parse a File Identifier Descriptor from raw bytes.
    ///
    /// Returns the parsed entry and the number of bytes consumed.
    pub fn parse(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 38 {
            return Err(Error::InvalidArgument);
        }
        let tag = DescriptorTag::parse(data)?;
        if tag.tag_id != TAG_FILE_IDENTIFIER {
            return Err(Error::InvalidArgument);
        }

        let file_version = read_u16_le(&data[16..18]);
        let file_characteristics = data[18];
        let id_length = data[19] as usize;
        let icb_location = read_u32_le(&data[20..24]);
        let icb_partition = read_u16_le(&data[24..26]);
        let impl_use_length = read_u16_le(&data[26..28]) as usize;

        let name_offset = 38 + impl_use_length;
        if name_offset + id_length > data.len() {
            return Err(Error::InvalidArgument);
        }

        let mut name = [0u8; MAX_NAME_LEN];
        let actual_len = id_length.min(MAX_NAME_LEN);
        if actual_len > 0 {
            name[..actual_len].copy_from_slice(&data[name_offset..name_offset + actual_len]);
        }

        // Total record length padded to 4-byte boundary.
        let raw_len = 38 + impl_use_length + id_length;
        let record_len = (raw_len + 3) & !3;

        Ok((
            Self {
                tag_id: tag.tag_id,
                file_version,
                file_characteristics,
                icb_location,
                icb_partition,
                name,
                name_len: actual_len,
                record_len,
            },
            record_len,
        ))
    }

    /// Returns `true` if this is a directory entry.
    pub fn is_directory(&self) -> bool {
        (self.file_characteristics & 0x02) != 0
    }

    /// Returns `true` if this entry has been deleted.
    pub fn is_deleted(&self) -> bool {
        (self.file_characteristics & 0x04) != 0
    }

    /// Returns `true` if this is the parent directory entry.
    pub fn is_parent(&self) -> bool {
        (self.file_characteristics & 0x08) != 0
    }

    /// Returns the filename as a byte slice.
    ///
    /// UDF names may use CS0 (compressed unicode) encoding. The first
    /// byte is the compression ID (8=UTF-8, 16=UTF-16).
    pub fn file_name(&self) -> &[u8] {
        if self.name_len > 1 {
            // Skip compression ID byte.
            &self.name[1..self.name_len]
        } else {
            &self.name[..self.name_len]
        }
    }
}

impl core::fmt::Debug for FileIdentifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FileIdentifier")
            .field("tag_id", &self.tag_id)
            .field("file_characteristics", &self.file_characteristics)
            .field("icb_location", &self.icb_location)
            .field("name_len", &self.name_len)
            .finish()
    }
}

// ── UdfRevision ──────────────────────────────────────────────────

/// UDF revision level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UdfRevision {
    /// Major version (e.g. 2 for UDF 2.60).
    pub major: u8,
    /// Minor version in hundredths (e.g. 60 for UDF 2.60).
    pub minor: u8,
}

impl UdfRevision {
    /// UDF 1.50.
    pub const V1_50: Self = Self {
        major: 1,
        minor: 50,
    };
    /// UDF 2.00.
    pub const V2_00: Self = Self { major: 2, minor: 0 };
    /// UDF 2.01.
    pub const V2_01: Self = Self { major: 2, minor: 1 };
    /// UDF 2.50.
    pub const V2_50: Self = Self {
        major: 2,
        minor: 50,
    };
    /// UDF 2.60.
    pub const V2_60: Self = Self {
        major: 2,
        minor: 60,
    };

    /// Parse a UDF revision from a BCD-encoded u16 (e.g. 0x0260).
    pub fn from_bcd(bcd: u16) -> Self {
        let major = ((bcd >> 8) & 0xFF) as u8;
        let minor = (bcd & 0xFF) as u8;
        Self { major, minor }
    }

    /// Returns `true` if this revision supports extended file entries.
    pub fn supports_extended_file_entry(&self) -> bool {
        self.major >= 2
    }
}

// ── UdfFs ────────────────────────────────────────────────────────

/// Mounted UDF filesystem handle.
///
/// Provides read-only access to files and directories on a UDF image.
/// Parses the AVDP, MVDS, and FSD at mount time.
pub struct UdfFs<'a> {
    /// Anchor Volume Descriptor Pointer.
    pub avdp: AnchorVolumeDescriptor,
    /// Partition descriptor.
    pub partition: UdfPartitionDescriptor,
    /// Logical volume descriptor.
    pub logical_volume: LogicalVolumeDescriptor,
    /// Detected UDF revision.
    pub revision: UdfRevision,
    /// Root ICB location (logical block).
    pub root_icb_location: u32,
    /// Root ICB partition reference.
    pub root_icb_partition: u16,
    /// Raw image data.
    data: &'a [u8],
}

impl<'a> UdfFs<'a> {
    /// Mount a UDF filesystem from raw image bytes.
    ///
    /// Parses the AVDP, scans the MVDS for partition and logical volume
    /// descriptors, and locates the root directory ICB.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the image is too small
    /// or missing required descriptors.
    pub fn mount(data: &'a [u8]) -> Result<Self> {
        let avdp_offset = AVDP_SECTOR * UDF_SECTOR_SIZE;
        if data.len() < avdp_offset + UDF_SECTOR_SIZE {
            return Err(Error::InvalidArgument);
        }

        let avdp = AnchorVolumeDescriptor::parse(&data[avdp_offset..])?;

        let mvds_start = avdp.mvds_location as usize * UDF_SECTOR_SIZE;
        let mvds_end = mvds_start + avdp.mvds_length as usize;
        if mvds_end > data.len() {
            return Err(Error::IoError);
        }

        let mut partition = None;
        let mut logical_volume = None;
        let mut _primary_vd_found = false;

        // Scan the MVDS for partition and logical volume descriptors.
        let mut sector_off = mvds_start;
        while sector_off + UDF_SECTOR_SIZE <= mvds_end {
            if sector_off + 16 > data.len() {
                break;
            }
            let tag_id = read_u16_le(&data[sector_off..sector_off + 2]);
            match tag_id {
                TAG_PRIMARY_VD => {
                    _primary_vd_found = true;
                }
                TAG_PARTITION_DESC => {
                    if let Ok(pd) = UdfPartitionDescriptor::parse(&data[sector_off..]) {
                        partition = Some(pd);
                    }
                }
                TAG_LOGICAL_VD => {
                    if let Ok(lvd) = LogicalVolumeDescriptor::parse(&data[sector_off..]) {
                        logical_volume = Some(lvd);
                    }
                }
                _ => {}
            }
            sector_off += UDF_SECTOR_SIZE;
        }

        let partition = partition.ok_or(Error::NotFound)?;
        let logical_volume = logical_volume.ok_or(Error::NotFound)?;

        // Locate the File Set Descriptor (FSD).
        let fsd_lbn = logical_volume.fsd_location;
        let fsd_abs = (partition.partition_start + fsd_lbn) as usize * UDF_SECTOR_SIZE;
        if fsd_abs + UDF_SECTOR_SIZE > data.len() {
            return Err(Error::IoError);
        }

        let fsd_tag = DescriptorTag::parse(&data[fsd_abs..])?;
        if fsd_tag.tag_id != TAG_FILE_SET_DESC {
            return Err(Error::InvalidArgument);
        }

        // Root directory ICB in the FSD at offset 400 (long_ad, 16 bytes).
        let root_icb_location = read_u32_le(&data[fsd_abs + 404..fsd_abs + 408]);
        let root_icb_partition = read_u16_le(&data[fsd_abs + 408..fsd_abs + 410]);

        let revision = UdfRevision::V2_01; // Default assumption.

        Ok(Self {
            avdp,
            partition,
            logical_volume,
            revision,
            root_icb_location,
            root_icb_partition,
            data,
        })
    }

    /// Convert a logical block number within the partition to an
    /// absolute byte offset in the image.
    pub fn lbn_to_offset(&self, lbn: u32) -> usize {
        (self.partition.partition_start + lbn) as usize * UDF_SECTOR_SIZE
    }

    /// Read a File Entry (tag 261) at the given logical block.
    pub fn read_file_entry(&self, lbn: u32) -> Result<FileEntry> {
        let offset = self.lbn_to_offset(lbn);
        if offset + UDF_SECTOR_SIZE > self.data.len() {
            return Err(Error::IoError);
        }
        FileEntry::parse(&self.data[offset..])
    }

    /// Read an Extended File Entry (tag 266) at the given logical block.
    pub fn read_extended_file_entry(&self, lbn: u32) -> Result<ExtendedFileEntry> {
        let offset = self.lbn_to_offset(lbn);
        if offset + UDF_SECTOR_SIZE > self.data.len() {
            return Err(Error::IoError);
        }
        ExtendedFileEntry::parse(&self.data[offset..])
    }

    /// Read directory entries from a directory ICB.
    ///
    /// The directory data is located by reading the file entry at `lbn`
    /// and following its allocation descriptors.
    pub fn readdir(&self, dir_lbn: u32) -> Result<([FileIdentifier; MAX_DIR_ENTRIES], usize)> {
        let fe_offset = self.lbn_to_offset(dir_lbn);
        if fe_offset + UDF_SECTOR_SIZE > self.data.len() {
            return Err(Error::IoError);
        }

        let tag_id = read_u16_le(&self.data[fe_offset..fe_offset + 2]);
        let (alloc_type, info_len, alloc_off, alloc_len) = if tag_id == TAG_FILE_ENTRY {
            let fe = FileEntry::parse(&self.data[fe_offset..])?;
            (
                fe.icb_tag.alloc_type(),
                fe.information_length,
                fe.alloc_descs_offset,
                fe.alloc_descs_length,
            )
        } else if tag_id == TAG_EXTENDED_FILE_ENTRY {
            let efe = ExtendedFileEntry::parse(&self.data[fe_offset..])?;
            (
                efe.icb_tag.alloc_type(),
                efe.information_length,
                efe.alloc_descs_offset,
                efe.alloc_descs_length,
            )
        } else {
            return Err(Error::InvalidArgument);
        };

        let mut entries = [FileIdentifier::empty(); MAX_DIR_ENTRIES];
        let mut count = 0;

        if alloc_type == ALLOC_TYPE_EMBEDDED {
            // Data is embedded in the allocation descriptors area.
            let embed_start = fe_offset + alloc_off;
            let embed_end = embed_start + (alloc_len as usize).min(info_len as usize);
            if embed_end > self.data.len() {
                return Err(Error::IoError);
            }
            let embed_data = &self.data[embed_start..embed_end];
            self.parse_fids(embed_data, &mut entries, &mut count);
        } else if alloc_type == ALLOC_TYPE_SHORT {
            let fe_data = &self.data[fe_offset..];
            let ad_start = alloc_off;
            let ad_end = ad_start + alloc_len as usize;
            let mut pos = ad_start;
            while pos + 8 <= ad_end && pos + 8 <= fe_data.len() {
                if let Ok(ad) = ShortAlloc::parse(&fe_data[pos..]) {
                    if ad.length() == 0 {
                        break;
                    }
                    let ext_off = self.lbn_to_offset(ad.extent_position);
                    let ext_end = ext_off + ad.length() as usize;
                    if ext_end <= self.data.len() {
                        self.parse_fids(&self.data[ext_off..ext_end], &mut entries, &mut count);
                    }
                }
                pos += 8;
            }
        } else if alloc_type == ALLOC_TYPE_LONG {
            let fe_data = &self.data[fe_offset..];
            let ad_start = alloc_off;
            let ad_end = ad_start + alloc_len as usize;
            let mut pos = ad_start;
            while pos + 16 <= ad_end && pos + 16 <= fe_data.len() {
                if let Ok(ad) = LongAlloc::parse(&fe_data[pos..]) {
                    if ad.length() == 0 {
                        break;
                    }
                    let ext_off = self.lbn_to_offset(ad.extent_location);
                    let ext_end = ext_off + ad.length() as usize;
                    if ext_end <= self.data.len() {
                        self.parse_fids(&self.data[ext_off..ext_end], &mut entries, &mut count);
                    }
                }
                pos += 16;
            }
        }

        Ok((entries, count))
    }

    /// Parse File Identifier Descriptors from a data slice.
    fn parse_fids(
        &self,
        data: &[u8],
        entries: &mut [FileIdentifier; MAX_DIR_ENTRIES],
        count: &mut usize,
    ) {
        let mut pos = 0;
        while pos < data.len() && *count < MAX_DIR_ENTRIES {
            match FileIdentifier::parse(&data[pos..]) {
                Ok((fid, consumed)) => {
                    if !fid.is_deleted() {
                        entries[*count] = fid;
                        *count += 1;
                    }
                    pos += consumed;
                }
                Err(_) => break,
            }
        }
    }

    /// Read file data for a file entry at the given logical block.
    ///
    /// Copies up to `buf.len()` bytes starting at `offset` within
    /// the file. Returns the number of bytes copied.
    pub fn read_file(&self, file_lbn: u32, offset: usize, buf: &mut [u8]) -> Result<usize> {
        let fe_offset = self.lbn_to_offset(file_lbn);
        if fe_offset + UDF_SECTOR_SIZE > self.data.len() {
            return Err(Error::IoError);
        }

        let tag_id = read_u16_le(&self.data[fe_offset..fe_offset + 2]);
        let (alloc_type, info_len, alloc_off, alloc_len) = if tag_id == TAG_FILE_ENTRY {
            let fe = FileEntry::parse(&self.data[fe_offset..])?;
            (
                fe.icb_tag.alloc_type(),
                fe.information_length as usize,
                fe.alloc_descs_offset,
                fe.alloc_descs_length,
            )
        } else if tag_id == TAG_EXTENDED_FILE_ENTRY {
            let efe = ExtendedFileEntry::parse(&self.data[fe_offset..])?;
            (
                efe.icb_tag.alloc_type(),
                efe.information_length as usize,
                efe.alloc_descs_offset,
                efe.alloc_descs_length,
            )
        } else {
            return Err(Error::InvalidArgument);
        };

        if offset >= info_len {
            return Ok(0);
        }

        let to_read = buf.len().min(info_len - offset);

        if alloc_type == ALLOC_TYPE_EMBEDDED {
            let embed_start = fe_offset + alloc_off + offset;
            let embed_end = embed_start + to_read;
            if embed_end > self.data.len() {
                return Err(Error::IoError);
            }
            buf[..to_read].copy_from_slice(&self.data[embed_start..embed_end]);
            return Ok(to_read);
        }

        // For short/long allocation descriptors, read extent data.
        let fe_data = &self.data[fe_offset..];
        let mut file_pos = 0usize;
        let mut buf_pos = 0usize;
        let ad_start = alloc_off;
        let ad_end = ad_start + alloc_len as usize;
        let ad_size = if alloc_type == ALLOC_TYPE_SHORT {
            8
        } else {
            16
        };

        let mut pos = ad_start;
        while pos + ad_size <= ad_end && pos + ad_size <= fe_data.len() && buf_pos < to_read {
            let (ext_lbn, ext_len) = if alloc_type == ALLOC_TYPE_SHORT {
                let ad = ShortAlloc::parse(&fe_data[pos..])?;
                (ad.extent_position, ad.length() as usize)
            } else {
                let ad = LongAlloc::parse(&fe_data[pos..])?;
                (ad.extent_location, ad.length() as usize)
            };

            if ext_len == 0 {
                break;
            }

            let ext_end_pos = file_pos + ext_len;
            if ext_end_pos > offset && file_pos < offset + to_read {
                let skip = if offset > file_pos {
                    offset - file_pos
                } else {
                    0
                };
                let avail = ext_len - skip;
                let copy_len = avail.min(to_read - buf_pos);
                let abs_off = self.lbn_to_offset(ext_lbn) + skip;
                if abs_off + copy_len > self.data.len() {
                    return Err(Error::IoError);
                }
                buf[buf_pos..buf_pos + copy_len]
                    .copy_from_slice(&self.data[abs_off..abs_off + copy_len]);
                buf_pos += copy_len;
            }

            file_pos += ext_len;
            pos += ad_size;
        }

        Ok(buf_pos)
    }

    /// Returns a reference to the raw image data.
    pub fn image(&self) -> &[u8] {
        self.data
    }

    /// Unmount the filesystem.
    pub fn unmount(self) {
        // Drop self.
    }
}

impl core::fmt::Debug for UdfFs<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UdfFs")
            .field("revision", &self.revision)
            .field("partition_start", &self.partition.partition_start)
            .field("partition_length", &self.partition.partition_length)
            .field("root_icb_location", &self.root_icb_location)
            .finish()
    }
}

// ── Helper functions ─────────────────────────────────────────────

/// Read a little-endian u16 from a 2-byte slice.
fn read_u16_le(data: &[u8]) -> u16 {
    u16::from_le_bytes([data[0], data[1]])
}

/// Read a little-endian u32 from a 4-byte slice.
fn read_u32_le(data: &[u8]) -> u32 {
    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
}

/// Read a little-endian u64 from an 8-byte slice.
fn read_u64_le(data: &[u8]) -> u64 {
    u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ])
}
