// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! UDF (Universal Disk Format) File Identifier Descriptor (directory entry).
//!
//! In UDF, directory entries are called File Identifier Descriptors (FIDs).
//! Each FID maps a file name to an ICB (Information Control Block) reference,
//! which identifies the file entry on disk.
//!
//! # FID Layout
//!
//! A FID has a variable-length structure:
//! 1. A 16-byte descriptor tag.
//! 2. A fixed 16-byte header (file characteristics, ICB location, lengths).
//! 3. Implementation Use area (L_IU bytes).
//! 4. File identifier (L_FI bytes, OSTA CS0 or UTF-8).
//! 5. Padding bytes to align to 4-byte boundary.
//!
//! # File Characteristics
//!
//! The `file_characteristics` byte encodes:
//! - Bit 0: Hidden file.
//! - Bit 1: This is the directory itself (`.`).
//! - Bit 2: This is deleted (equivalent to a tombstone entry).
//! - Bit 3: This is the parent directory (`..`).

use oncrix_lib::{Error, Result};

/// FID file characteristic flags.
pub mod fc {
    /// File is hidden.
    pub const HIDDEN: u8 = 0x01;
    /// FID refers to the directory itself (`.`).
    pub const DIRECTORY_SELF: u8 = 0x02;
    /// FID is deleted.
    pub const DELETED: u8 = 0x04;
    /// FID refers to the parent directory (`..`).
    pub const PARENT: u8 = 0x08;
    /// File is a metadata stream.
    pub const METADATA: u8 = 0x10;
}

/// An ICB (Information Control Block) location — a long_ad that identifies
/// where the File Entry resides.
#[derive(Clone, Copy, Default)]
pub struct IcbLocation {
    /// Extent length + type.
    pub extent_len: u32,
    /// Logical block number.
    pub lbn: u32,
    /// Partition reference number.
    pub partition_ref: u16,
}

impl IcbLocation {
    /// Parses an ICB location from 10 bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 10 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            extent_len: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            lbn: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            partition_ref: u16::from_le_bytes([b[8], b[9]]),
        })
    }

    /// Returns the data length of this ICB.
    pub const fn length(&self) -> u32 {
        self.extent_len & 0x3FFF_FFFF
    }
}

/// Minimum size of the fixed FID header (not including tag).
pub const FID_FIXED_SIZE: usize = 20;

/// A UDF File Identifier Descriptor.
pub struct Fid {
    /// File characteristics.
    pub file_characteristics: u8,
    /// Length of the file identifier (L_FI bytes).
    pub file_id_length: u8,
    /// ICB location.
    pub icb: IcbLocation,
    /// Length of the implementation use area (L_IU bytes).
    pub impl_use_length: u16,
    /// File identifier bytes (OSTA CS0 or UTF-8, up to 255 bytes).
    pub file_id: [u8; 256],
    /// Actual file identifier byte count.
    pub file_id_len: usize,
}

impl Default for Fid {
    fn default() -> Self {
        Self {
            file_characteristics: 0,
            file_id_length: 0,
            icb: IcbLocation::default(),
            impl_use_length: 0,
            file_id: [0u8; 256],
            file_id_len: 0,
        }
    }
}

impl Fid {
    /// Parses a FID from a raw byte slice (starting after the descriptor tag).
    ///
    /// Returns the FID and the total byte length consumed (for advancing to
    /// the next FID in the directory stream).
    pub fn from_bytes(b: &[u8]) -> Result<(Self, usize)> {
        if b.len() < FID_FIXED_SIZE {
            return Err(Error::InvalidArgument);
        }
        let file_characteristics = b[0];
        let file_id_length = b[1];
        let icb = IcbLocation::from_bytes(&b[2..12])?;
        let impl_use_length = u16::from_le_bytes([b[12], b[13]]);

        let header_end = FID_FIXED_SIZE + impl_use_length as usize;
        if b.len() < header_end + file_id_length as usize {
            return Err(Error::InvalidArgument);
        }

        let id_start = header_end;
        let _id_end = id_start + file_id_length as usize;
        let mut fid = Fid {
            file_characteristics,
            file_id_length,
            icb,
            impl_use_length,
            ..Fid::default()
        };
        let copy_len = (file_id_length as usize).min(255);
        fid.file_id[..copy_len].copy_from_slice(&b[id_start..id_start + copy_len]);
        fid.file_id_len = copy_len;

        // Total size rounded up to 4-byte boundary.
        let raw_size = header_end + file_id_length as usize;
        let padded_size = (raw_size + 3) & !3;

        Ok((fid, padded_size))
    }

    /// Returns `true` if this FID is the parent directory entry.
    pub const fn is_parent(&self) -> bool {
        self.file_characteristics & fc::PARENT != 0
    }

    /// Returns `true` if this FID refers to the directory itself.
    pub const fn is_self(&self) -> bool {
        self.file_characteristics & fc::DIRECTORY_SELF != 0
    }

    /// Returns `true` if this FID is deleted.
    pub const fn is_deleted(&self) -> bool {
        self.file_characteristics & fc::DELETED != 0
    }

    /// Returns `true` if this FID is hidden.
    pub const fn is_hidden(&self) -> bool {
        self.file_characteristics & fc::HIDDEN != 0
    }

    /// Returns the file identifier bytes.
    pub fn name_bytes(&self) -> &[u8] {
        &self.file_id[..self.file_id_len]
    }
}

/// Iterator over UDF FIDs in a directory data buffer.
pub struct FidIter<'a> {
    data: &'a [u8],
    /// Current byte offset (past the descriptor tag of the current FID).
    offset: usize,
}

impl<'a> FidIter<'a> {
    /// Creates a new FID iterator.
    ///
    /// `offset` is where the first FID body begins (after the 16-byte descriptor tag
    /// of the directory's file entry; typically 0 for a pre-sliced buffer).
    pub const fn new(data: &'a [u8], offset: usize) -> Self {
        Self { data, offset }
    }

    /// Returns the next FID, skipping deleted entries.
    pub fn next_fid(&mut self) -> Result<Option<Fid>> {
        loop {
            if self.offset >= self.data.len() {
                return Ok(None);
            }
            let remaining = &self.data[self.offset..];
            if remaining.len() < FID_FIXED_SIZE {
                return Ok(None);
            }

            let (fid, size) = Fid::from_bytes(remaining)?;
            self.offset += size;

            if !fid.is_deleted() {
                return Ok(Some(fid));
            }
        }
    }
}
