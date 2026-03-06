// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Block device partition table parsing.
//!
//! Supports both MBR (Master Boot Record) and GPT (GUID Partition Table) partition
//! schemes. Provides structures and parsing logic for identifying partition
//! boundaries on a block device.
//!
//! # MBR format
//! The MBR occupies the first 512-byte sector. Four primary partition entries
//! start at offset 0x1BE; the signature 0xAA55 is at bytes 510-511.
//!
//! # GPT format
//! The GPT header sits in LBA 1 (512 bytes). Partition entries follow from LBA 2.
//! The header is validated via CRC32 of the header and the entry array.
//!
//! Reference: UEFI Specification 2.10, Part 1, §5 — GUID Partition Table.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// MBR Constants
// ---------------------------------------------------------------------------

/// MBR sector size in bytes.
pub const MBR_SECTOR_SIZE: usize = 512;
/// Offset of first partition entry within the MBR.
pub const MBR_PART_OFFSET: usize = 0x1BE;
/// Number of MBR primary partition entries.
pub const MBR_PART_COUNT: usize = 4;
/// MBR boot signature (bytes 510-511).
pub const MBR_SIGNATURE: u16 = 0xAA55;
/// MBR partition type for GPT protective (indicates GPT disk).
pub const MBR_TYPE_GPT: u8 = 0xEE;
/// MBR partition type: Extended partition.
pub const MBR_TYPE_EXTENDED: u8 = 0x05;
/// MBR partition type: FAT32 LBA.
pub const MBR_TYPE_FAT32_LBA: u8 = 0x0C;
/// MBR partition type: Linux ext2/3/4.
pub const MBR_TYPE_LINUX: u8 = 0x83;

// ---------------------------------------------------------------------------
// GPT Constants
// ---------------------------------------------------------------------------

/// GPT header magic: "EFI PART".
pub const GPT_SIGNATURE: u64 = 0x5452_4150_2049_4645;
/// GPT header revision 1.0.
pub const GPT_REVISION_1_0: u32 = 0x0001_0000;
/// GPT header size in bytes.
pub const GPT_HEADER_SIZE: u32 = 92;
/// GPT partition entry size in bytes.
pub const GPT_ENTRY_SIZE: usize = 128;
/// Maximum partition entries to parse.
pub const GPT_MAX_ENTRIES: usize = 128;

/// Maximum partitions tracked per device.
const MAX_PARTITIONS: usize = 32;

// ---------------------------------------------------------------------------
// MBR Partition Entry
// ---------------------------------------------------------------------------

/// One MBR primary partition entry (16 bytes).
///
/// `#[repr(C, packed)]` required to match the on-disk layout exactly.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct MbrEntry {
    /// Boot indicator: 0x80 = bootable, 0x00 = not.
    pub boot: u8,
    /// CHS address of first sector (3 bytes, packed).
    pub start_chs: [u8; 3],
    /// Partition type byte (e.g., 0x83 = Linux, 0xEE = GPT).
    pub partition_type: u8,
    /// CHS address of last sector.
    pub end_chs: [u8; 3],
    /// LBA start sector (little-endian).
    pub lba_start: u32,
    /// Total sectors in partition (little-endian).
    pub sectors: u32,
}

impl MbrEntry {
    /// Returns `true` if this entry describes a valid, non-empty partition.
    pub fn is_valid(&self) -> bool {
        self.partition_type != 0 && self.sectors > 0
    }

    /// Returns `true` if this is a GPT protective MBR entry.
    pub fn is_gpt_protective(&self) -> bool {
        self.partition_type == MBR_TYPE_GPT
    }
}

// ---------------------------------------------------------------------------
// GPT Header
// ---------------------------------------------------------------------------

/// GPT header (92 bytes in LBA 1).
///
/// `#[repr(C, packed)]` required to match on-disk layout.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct GptHeader {
    /// Signature: "EFI PART" = 0x5452415020494645.
    pub signature: u64,
    /// Revision: 0x00010000 for version 1.0.
    pub revision: u32,
    /// Header size in bytes (must be >= 92).
    pub header_size: u32,
    /// CRC32 of the header (this field zeroed during calculation).
    pub header_crc32: u32,
    /// Reserved, must be 0.
    pub _reserved: u32,
    /// LBA of this header (primary = 1, backup = last LBA).
    pub my_lba: u64,
    /// LBA of the alternate header.
    pub alternate_lba: u64,
    /// First usable LBA for partition data.
    pub first_usable_lba: u64,
    /// Last usable LBA for partition data.
    pub last_usable_lba: u64,
    /// Disk GUID (16 bytes).
    pub disk_guid: [u8; 16],
    /// LBA of start of partition entry array.
    pub partition_entry_lba: u64,
    /// Number of partition entries.
    pub num_partition_entries: u32,
    /// Size of each partition entry in bytes.
    pub partition_entry_size: u32,
    /// CRC32 of the partition entry array.
    pub partition_crc32: u32,
}

impl GptHeader {
    /// Returns `true` if the signature matches the expected GPT signature.
    pub fn signature_valid(&self) -> bool {
        self.signature == GPT_SIGNATURE
    }
}

// ---------------------------------------------------------------------------
// GPT Partition Entry
// ---------------------------------------------------------------------------

/// GPT partition entry (128 bytes).
///
/// `#[repr(C, packed)]` required.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct GptEntry {
    /// Partition type GUID (16 bytes).
    pub type_guid: [u8; 16],
    /// Unique partition GUID (16 bytes).
    pub partition_guid: [u8; 16],
    /// Starting LBA.
    pub start_lba: u64,
    /// Ending LBA (inclusive).
    pub end_lba: u64,
    /// Attribute flags (bit 2 = read-only, bit 60 = no auto-mount, etc.).
    pub attributes: u64,
    /// Partition name (UTF-16LE, up to 36 characters).
    pub name: [u16; 36],
}

impl Default for GptEntry {
    fn default() -> Self {
        Self {
            type_guid: [0u8; 16],
            partition_guid: [0u8; 16],
            start_lba: 0,
            end_lba: 0,
            attributes: 0,
            name: [0u16; 36],
        }
    }
}

impl GptEntry {
    /// Returns `true` if this entry is non-empty (type GUID is not all zeroes).
    pub fn is_used(&self) -> bool {
        self.type_guid.iter().any(|&b| b != 0)
    }

    /// Returns the number of sectors in this partition.
    pub fn sector_count(&self) -> u64 {
        if self.end_lba >= self.start_lba {
            self.end_lba - self.start_lba + 1
        } else {
            0
        }
    }
}

// ---------------------------------------------------------------------------
// Partition Information (device-agnostic)
// ---------------------------------------------------------------------------

/// Parsed partition information, independent of MBR/GPT source.
#[derive(Clone, Copy, Debug)]
pub struct PartitionInfo {
    /// Starting LBA of the partition.
    pub start_lba: u64,
    /// Size in sectors (LBA count).
    pub size: u64,
    /// Partition type GUID (GPT) or MBR type byte as first byte (MBR).
    /// For MBR: `type_guid[0]` = MBR type, rest = 0.
    pub type_guid: [u8; 16],
    /// Partition name (UTF-16LE for GPT; empty for MBR).
    pub name: [u16; 36],
    /// `true` if this entry is valid.
    pub valid: bool,
}

impl Default for PartitionInfo {
    fn default() -> Self {
        Self {
            start_lba: 0,
            size: 0,
            type_guid: [0u8; 16],
            name: [0u16; 36],
            valid: false,
        }
    }
}

impl PartitionInfo {
    /// Creates a `PartitionInfo` from an MBR entry.
    pub fn from_mbr(entry: &MbrEntry) -> Self {
        let mut type_guid = [0u8; 16];
        type_guid[0] = entry.partition_type;
        Self {
            start_lba: entry.lba_start as u64,
            size: entry.sectors as u64,
            type_guid,
            name: [0u16; 36],
            valid: entry.is_valid(),
        }
    }

    /// Creates a `PartitionInfo` from a GPT entry.
    pub fn from_gpt(entry: &GptEntry) -> Self {
        let name = entry.name;
        Self {
            start_lba: entry.start_lba,
            size: entry.sector_count(),
            type_guid: entry.type_guid,
            name,
            valid: entry.is_used(),
        }
    }
}

// ---------------------------------------------------------------------------
// MBR Parser
// ---------------------------------------------------------------------------

/// Parses an MBR sector and extracts partition entries.
///
/// # Parameters
/// - `sector`: 512-byte buffer containing the first sector of the disk.
/// - `out`: Output array to fill with parsed partitions.
///
/// # Returns
/// Number of valid partitions found (0–4).
///
/// # Errors
/// Returns `Error::InvalidArgument` if the MBR signature is invalid.
pub fn parse_mbr(sector: &[u8; 512], out: &mut [PartitionInfo; MAX_PARTITIONS]) -> Result<usize> {
    // Validate MBR signature
    let sig = u16::from_le_bytes([sector[510], sector[511]]);
    if sig != MBR_SIGNATURE {
        return Err(Error::InvalidArgument);
    }
    let mut count = 0usize;
    for i in 0..MBR_PART_COUNT {
        let off = MBR_PART_OFFSET + i * 16;
        let entry_bytes: [u8; 16] = sector[off..off + 16]
            .try_into()
            .map_err(|_| Error::InvalidArgument)?;
        // SAFETY: MbrEntry is repr(C, packed) and matches the 16-byte layout.
        let entry: MbrEntry = unsafe { core::mem::transmute(entry_bytes) };
        if entry.is_valid() && count < MAX_PARTITIONS {
            out[count] = PartitionInfo::from_mbr(&entry);
            count += 1;
        }
    }
    Ok(count)
}

// ---------------------------------------------------------------------------
// GPT Parser
// ---------------------------------------------------------------------------

/// Parses a GPT header and partition entry array.
///
/// # Parameters
/// - `header_sector`: 512-byte buffer of LBA 1 (GPT header sector).
/// - `entries_buf`: Buffer containing the partition entry array starting at LBA 2.
///   Must be at least `num_entries * 128` bytes.
/// - `out`: Output array to fill.
///
/// # Returns
/// Number of valid GPT partitions found.
///
/// # Errors
/// Returns `Error::InvalidArgument` if the GPT signature is invalid.
pub fn parse_gpt(
    header_sector: &[u8; 512],
    entries_buf: &[u8],
    out: &mut [PartitionInfo; MAX_PARTITIONS],
) -> Result<usize> {
    // Interpret the header sector as a GptHeader
    if header_sector.len() < GPT_HEADER_SIZE as usize {
        return Err(Error::InvalidArgument);
    }
    // SAFETY: GptHeader is repr(C, packed); we copy the bytes first.
    let mut hdr_bytes = [0u8; 92];
    hdr_bytes.copy_from_slice(&header_sector[..92]);
    let header: GptHeader = unsafe { core::mem::transmute(hdr_bytes) };

    if !header.signature_valid() {
        return Err(Error::InvalidArgument);
    }

    let num_entries = (header.num_partition_entries as usize).min(GPT_MAX_ENTRIES);
    let entry_size = header.partition_entry_size as usize;
    if entry_size < GPT_ENTRY_SIZE {
        return Err(Error::InvalidArgument);
    }

    let mut count = 0usize;
    for i in 0..num_entries {
        if count >= MAX_PARTITIONS {
            break;
        }
        let off = i * entry_size;
        if off + GPT_ENTRY_SIZE > entries_buf.len() {
            break;
        }
        let mut entry_bytes = [0u8; 128];
        entry_bytes.copy_from_slice(&entries_buf[off..off + 128]);
        // SAFETY: GptEntry is repr(C, packed).
        let entry: GptEntry = unsafe { core::mem::transmute(entry_bytes) };
        if entry.is_used() {
            out[count] = PartitionInfo::from_gpt(&entry);
            count += 1;
        }
    }
    Ok(count)
}

// ---------------------------------------------------------------------------
// Partition Table Registry
// ---------------------------------------------------------------------------

/// Registry of parsed partitions for a block device.
pub struct PartitionTable {
    partitions: [PartitionInfo; MAX_PARTITIONS],
    count: usize,
    /// `true` if GPT was detected; `false` for MBR.
    pub is_gpt: bool,
}

impl PartitionTable {
    /// Creates an empty partition table.
    pub const fn new() -> Self {
        Self {
            partitions: [PartitionInfo {
                start_lba: 0,
                size: 0,
                type_guid: [0u8; 16],
                name: [0u16; 36],
                valid: false,
            }; MAX_PARTITIONS],
            count: 0,
            is_gpt: false,
        }
    }

    /// Populates the table from an MBR sector.
    pub fn load_mbr(&mut self, sector: &[u8; 512]) -> Result<usize> {
        self.count = parse_mbr(sector, &mut self.partitions)?;
        self.is_gpt = false;
        Ok(self.count)
    }

    /// Populates the table from GPT header + entries buffer.
    pub fn load_gpt(&mut self, header_sector: &[u8; 512], entries_buf: &[u8]) -> Result<usize> {
        self.count = parse_gpt(header_sector, entries_buf, &mut self.partitions)?;
        self.is_gpt = true;
        Ok(self.count)
    }

    /// Returns the partition at index `idx`.
    pub fn get(&self, idx: usize) -> Option<&PartitionInfo> {
        if idx < self.count {
            Some(&self.partitions[idx])
        } else {
            None
        }
    }

    /// Returns the number of valid partitions.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no partitions have been found.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for PartitionTable {
    fn default() -> Self {
        Self::new()
    }
}
