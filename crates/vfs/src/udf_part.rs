// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! UDF (Universal Disk Format) partition descriptor and access layer.
//!
//! UDF is the standard filesystem for DVDs and Blu-ray discs, defined by
//! OSTA (Optical Storage Technology Association). This module implements
//! partition descriptor parsing and logical block address translation.
//!
//! # Partition Types
//!
//! UDF supports several partition access types:
//! - **Physical**: Direct LBA access (most common).
//! - **Virtual**: Remapping via Virtual Allocation Table (VAT) for write-once media.
//! - **Sparable**: Sector sparing table for rewritable media.
//! - **Metadata**: Mirrored metadata for reliability (UDF 2.50+).
//!
//! # Descriptor Tags
//!
//! All UDF structures begin with a 16-byte `DescriptorTag` that identifies
//! the structure type, version, checksum, and serial number.

use oncrix_lib::{Error, Result};

/// UDF sector size for standard optical media.
pub const UDF_SECTOR_SIZE: u32 = 2048;

/// Tag identifier values for UDF descriptors (ECMA-167 §7.2).
pub mod tag_id {
    pub const PRIMARY_VOL_DESC: u16 = 1;
    pub const ANCHOR_VOL_DESC_PTR: u16 = 2;
    pub const VOL_DESC_PTR: u16 = 3;
    pub const IMP_USE_VOL_DESC: u16 = 4;
    pub const PARTITION_DESC: u16 = 5;
    pub const LOGICAL_VOL_DESC: u16 = 6;
    pub const UNALLOC_SPACE_DESC: u16 = 7;
    pub const TERMINATING_DESC: u16 = 8;
    pub const LOGICAL_VOL_INTEGRITY_DESC: u16 = 9;
    pub const FILE_SET_DESC: u16 = 256;
    pub const FILE_IDENTIFIER_DESC: u16 = 257;
    pub const EXTENDED_ATTR_HDR_DESC: u16 = 258;
    pub const INDIRECT_ENTRY: u16 = 259;
    pub const TERMINAL_ENTRY: u16 = 260;
    pub const FILE_ENTRY: u16 = 261;
    pub const EXTENDED_FILE_ENTRY: u16 = 266;
}

/// Partition access types (ECMA-167 §10.7.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum PartitionAccessType {
    /// Unspecified / read-write.
    ReadWrite = 0,
    /// Write-once media.
    WriteOnce = 1,
    /// Rewritable media.
    Rewritable = 2,
    /// Overwritable media.
    Overwritable = 3,
}

impl PartitionAccessType {
    /// Parses an access type from its raw u16 value.
    pub fn from_u16(val: u16) -> Self {
        match val {
            1 => Self::WriteOnce,
            2 => Self::Rewritable,
            3 => Self::Overwritable,
            _ => Self::ReadWrite,
        }
    }
}

/// UDF Descriptor Tag (ECMA-167 §7.2, 16 bytes).
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct DescriptorTag {
    /// Tag identifier.
    pub tag_id: u16,
    /// Descriptor version.
    pub desc_ver: u16,
    /// Tag checksum.
    pub tag_checksum: u8,
    /// Tag serial number.
    pub tag_serial_num: u8,
    /// Descriptor CRC.
    pub desc_crc: u16,
    /// Descriptor CRC length.
    pub desc_crc_len: u16,
    /// Tag location (LBA of this descriptor).
    pub tag_location: u32,
}

impl DescriptorTag {
    /// Parses a descriptor tag from a 16-byte slice.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 16 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            tag_id: u16::from_le_bytes([b[0], b[1]]),
            desc_ver: u16::from_le_bytes([b[2], b[3]]),
            tag_checksum: b[4],
            tag_serial_num: b[5],
            desc_crc: u16::from_le_bytes([b[6], b[7]]),
            desc_crc_len: u16::from_le_bytes([b[8], b[9]]),
            tag_location: u32::from_le_bytes([b[10], b[11], b[12], b[13]]),
        })
    }

    /// Validates the tag checksum (sum of bytes 0..4 and 6..16 mod 256 == byte 4).
    pub fn verify_checksum(&self, raw: &[u8]) -> bool {
        if raw.len() < 16 {
            return false;
        }
        let mut sum: u8 = 0;
        for (i, &b) in raw[..16].iter().enumerate() {
            if i != 4 {
                sum = sum.wrapping_add(b);
            }
        }
        sum == self.tag_checksum
    }
}

/// UDF Partition Descriptor (ECMA-167 §10.5).
#[derive(Clone, Copy)]
pub struct PartitionDescriptor {
    /// Descriptor tag.
    pub tag: DescriptorTag,
    /// Volume descriptor sequence number.
    pub vol_desc_seq_num: u32,
    /// Partition flags (bit 0 = allocated).
    pub partition_flags: u16,
    /// Partition number.
    pub partition_number: u16,
    /// Partition access type.
    pub access_type: PartitionAccessType,
    /// Starting location of the partition (in sectors).
    pub partition_starting_location: u32,
    /// Length of the partition in sectors.
    pub partition_length: u32,
}

impl Default for PartitionDescriptor {
    fn default() -> Self {
        Self {
            tag: DescriptorTag::default(),
            vol_desc_seq_num: 0,
            partition_flags: 0,
            partition_number: 0,
            access_type: PartitionAccessType::ReadWrite,
            partition_starting_location: 0,
            partition_length: 0,
        }
    }
}

impl PartitionDescriptor {
    /// Parses a Partition Descriptor from a raw sector buffer (at least 512 bytes).
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 512 {
            return Err(Error::InvalidArgument);
        }
        let tag = DescriptorTag::from_bytes(&b[0..16])?;
        if tag.tag_id != tag_id::PARTITION_DESC {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            tag,
            vol_desc_seq_num: u32::from_le_bytes([b[16], b[17], b[18], b[19]]),
            partition_flags: u16::from_le_bytes([b[20], b[21]]),
            partition_number: u16::from_le_bytes([b[22], b[23]]),
            // Partition contents (32 bytes starting at offset 24) — skipped.
            access_type: PartitionAccessType::from_u16(u16::from_le_bytes([b[56], b[57]])),
            partition_starting_location: u32::from_le_bytes([b[58], b[59], b[60], b[61]]),
            partition_length: u32::from_le_bytes([b[62], b[63], b[64], b[65]]),
        })
    }

    /// Returns `true` if the allocated flag is set in `partition_flags`.
    pub const fn is_allocated(&self) -> bool {
        self.partition_flags & 0x0001 != 0
    }

    /// Translates a logical block address (relative to partition start) to
    /// an absolute sector number on the volume.
    pub fn lba_to_sector(&self, lba: u32) -> Result<u32> {
        if lba >= self.partition_length {
            return Err(Error::InvalidArgument);
        }
        Ok(self.partition_starting_location + lba)
    }
}

/// A Logical Block Address (LBA) within a UDF partition.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Lb {
    /// Partition reference number.
    pub partition_ref: u16,
    /// Logical block number within the partition.
    pub lbn: u32,
}

impl Lb {
    /// Creates a new `Lb` for the given partition and block number.
    pub const fn new(partition_ref: u16, lbn: u32) -> Self {
        Self { partition_ref, lbn }
    }

    /// Parses a Long Allocation Descriptor (6 bytes) into an `Lb`.
    ///
    /// The Long AD has a 4-byte length + type field followed by a 6-byte LB address.
    pub fn from_long_ad(b: &[u8]) -> Result<(Self, u32)> {
        if b.len() < 10 {
            return Err(Error::InvalidArgument);
        }
        let raw_len = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        // Upper 2 bits of length encode the extent type (0 = recorded, 1 = unrecorded, 2 = alloc).
        let extent_len = raw_len & 0x3FFF_FFFF;
        let partition_ref = u16::from_le_bytes([b[4], b[5]]);
        let lbn = u32::from_le_bytes([b[6], b[7], b[8], b[9]]);
        Ok((Self { partition_ref, lbn }, extent_len))
    }
}

/// UDF partition map table (simplified, physical partitions only).
pub struct PartitionMap {
    /// Registered partition descriptors (up to 4).
    partitions: [PartitionDescriptor; 4],
    /// Number of registered partitions.
    count: usize,
}

impl Default for PartitionMap {
    fn default() -> Self {
        Self {
            partitions: [PartitionDescriptor::default(); 4],
            count: 0,
        }
    }
}

impl PartitionMap {
    /// Creates an empty partition map.
    pub const fn new() -> Self {
        Self {
            partitions: [PartitionDescriptor {
                tag: DescriptorTag {
                    tag_id: 0,
                    desc_ver: 0,
                    tag_checksum: 0,
                    tag_serial_num: 0,
                    desc_crc: 0,
                    desc_crc_len: 0,
                    tag_location: 0,
                },
                vol_desc_seq_num: 0,
                partition_flags: 0,
                partition_number: 0,
                access_type: PartitionAccessType::ReadWrite,
                partition_starting_location: 0,
                partition_length: 0,
            }; 4],
            count: 0,
        }
    }

    /// Registers a partition descriptor.
    pub fn register(&mut self, pd: PartitionDescriptor) -> Result<()> {
        if self.count >= 4 {
            return Err(Error::OutOfMemory);
        }
        self.partitions[self.count] = pd;
        self.count += 1;
        Ok(())
    }

    /// Resolves a logical block address to an absolute sector number.
    pub fn resolve(&self, lb: &Lb) -> Result<u32> {
        for pd in &self.partitions[..self.count] {
            if pd.partition_number == lb.partition_ref {
                return pd.lba_to_sector(lb.lbn);
            }
        }
        Err(Error::NotFound)
    }
}
