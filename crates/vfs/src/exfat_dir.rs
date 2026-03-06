// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! exFAT directory entry parsing and iteration.
//!
//! exFAT directories contain a sequence of 32-byte directory entries.
//! Unlike FAT32, exFAT uses a set of typed entry records rather than
//! a monolithic structure:
//! - `0x85 STREAM_EXT`: Primary file entry metadata.
//! - `0xC0 FILE_NAME`: File name chunk (15 UTF-16 chars each).
//! - `0xC1 FILE_NAME_EXT` (continuation): Additional name chunks.
//! - `0x81 VOLUME_LABEL`: Volume label entry.
//! - `0x82 ALLOCATION_BITMAP`: Allocation bitmap metadata.
//! - `0x83 UPCASE_TABLE`: Case-conversion table metadata.
//!
//! Each file is described by a "set" starting with a `FILE` entry (type 0x85),
//! followed by a `STREAM_EXT` entry, then one or more `FILE_NAME` entries.

use oncrix_lib::{Error, Result};

/// exFAT directory entry types.
pub mod entry_type {
    pub const END_OF_DIR: u8 = 0x00;
    pub const ALLOCATION_BITMAP: u8 = 0x81;
    pub const UPCASE_TABLE: u8 = 0x82;
    pub const VOLUME_LABEL: u8 = 0x83;
    pub const FILE: u8 = 0x85;
    pub const STREAM_EXTENSION: u8 = 0xC0;
    pub const FILE_NAME: u8 = 0xC1;
    pub const DELETED: u8 = 0x20; // bit 6 clear = deleted
}

/// Size of an exFAT directory entry.
pub const EXFAT_ENTRY_SIZE: usize = 32;

/// Maximum number of file-name entries per file (15 chars * 17 entries = 255 chars).
pub const EXFAT_MAX_NAME_ENTRIES: usize = 17;

/// Attributes for exFAT `FILE` entries.
pub mod attr {
    pub const ATTR_READ_ONLY: u16 = 0x0001;
    pub const ATTR_HIDDEN: u16 = 0x0002;
    pub const ATTR_SYSTEM: u16 = 0x0004;
    pub const ATTR_DIRECTORY: u16 = 0x0010;
    pub const ATTR_ARCHIVE: u16 = 0x0020;
}

/// An exFAT `FILE` directory entry (type 0x85).
#[derive(Clone, Copy, Default)]
pub struct ExfatFileEntry {
    /// Number of secondary entries following this one (2 + name_entry_count).
    pub secondary_count: u8,
    /// Set checksum over all entries in the set.
    pub set_checksum: u16,
    /// File attributes.
    pub file_attributes: u16,
    /// Creation UTC offset (in units of 15 minutes).
    pub create_utc_offset: u8,
    /// Last modified UTC offset.
    pub modified_utc_offset: u8,
    /// Last accessed UTC offset.
    pub access_utc_offset: u8,
    /// Creation timestamp (DOS format).
    pub create_time: u32,
    /// Last-modified timestamp (DOS format).
    pub modified_time: u32,
    /// Last-accessed timestamp (DOS format).
    pub access_time: u32,
}

impl ExfatFileEntry {
    /// Parses a FILE entry from 32 raw bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < EXFAT_ENTRY_SIZE || b[0] != entry_type::FILE {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            secondary_count: b[1],
            set_checksum: u16::from_le_bytes([b[2], b[3]]),
            file_attributes: u16::from_le_bytes([b[4], b[5]]),
            create_utc_offset: b[6],
            modified_utc_offset: b[7],
            access_utc_offset: b[8],
            create_time: u32::from_le_bytes([b[9], b[10], b[11], b[12]]),
            modified_time: u32::from_le_bytes([b[13], b[14], b[15], b[16]]),
            access_time: u32::from_le_bytes([b[17], b[18], b[19], b[20]]),
        })
    }

    /// Returns `true` if this entry represents a directory.
    pub const fn is_dir(&self) -> bool {
        self.file_attributes & attr::ATTR_DIRECTORY != 0
    }

    /// Returns `true` if this entry is read-only.
    pub const fn is_read_only(&self) -> bool {
        self.file_attributes & attr::ATTR_READ_ONLY != 0
    }
}

/// An exFAT `STREAM_EXTENSION` directory entry (type 0xC0).
#[derive(Clone, Copy, Default)]
pub struct ExfatStreamExt {
    /// Stream extension flags (bit 0: AllocationPossible, bit 1: NoFatChain).
    pub flags: u8,
    /// Length of the file name in characters (UTF-16 units).
    pub name_length: u8,
    /// Checksum of the name.
    pub name_hash: u16,
    /// Valid data length (bytes actually written; may be < data_length).
    pub valid_data_length: u64,
    /// First cluster of the data.
    pub first_cluster: u32,
    /// Total allocated size of the data in bytes.
    pub data_length: u64,
}

impl ExfatStreamExt {
    /// Parses a STREAM_EXTENSION entry from 32 raw bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < EXFAT_ENTRY_SIZE || b[0] != entry_type::STREAM_EXTENSION {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            flags: b[1],
            name_length: b[3],
            name_hash: u16::from_le_bytes([b[4], b[5]]),
            valid_data_length: u64::from_le_bytes([
                b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
            ]),
            first_cluster: u32::from_le_bytes([b[20], b[21], b[22], b[23]]),
            data_length: u64::from_le_bytes([
                b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31],
            ]),
        })
    }

    /// Returns `true` if the data is contiguous (no-FAT-chain flag set).
    pub const fn is_contiguous(&self) -> bool {
        self.flags & 0x02 != 0
    }
}

/// An exFAT `FILE_NAME` directory entry (type 0xC1).
#[derive(Clone, Copy, Default)]
pub struct ExfatFileName {
    /// Flags (must be 0).
    pub flags: u8,
    /// Up to 15 UTF-16LE characters.
    pub name: [u16; 15],
}

impl ExfatFileName {
    /// Parses a FILE_NAME entry from 32 raw bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < EXFAT_ENTRY_SIZE || b[0] != entry_type::FILE_NAME {
            return Err(Error::InvalidArgument);
        }
        let mut name = [0u16; 15];
        for i in 0..15 {
            name[i] = u16::from_le_bytes([b[2 + i * 2], b[3 + i * 2]]);
        }
        Ok(Self { flags: b[1], name })
    }
}

/// A fully decoded exFAT directory entry set.
pub struct ExfatDirEntrySet {
    /// FILE entry metadata.
    pub file_entry: ExfatFileEntry,
    /// STREAM_EXTENSION metadata.
    pub stream: ExfatStreamExt,
    /// Reassembled filename (UTF-16LE, up to 255 chars + null).
    pub name: [u16; 256],
    /// Actual character count in `name`.
    pub name_len: usize,
}

impl Default for ExfatDirEntrySet {
    fn default() -> Self {
        Self {
            file_entry: ExfatFileEntry::default(),
            stream: ExfatStreamExt::default(),
            name: [0u16; 256],
            name_len: 0,
        }
    }
}

/// Iterator over exFAT directory entries in a raw block.
pub struct ExfatDirIter<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> ExfatDirIter<'a> {
    /// Creates a new iterator.
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    /// Reads the next decoded directory entry set.
    ///
    /// Skips deleted and non-file entries; stops at end-of-directory.
    pub fn next_entry(&mut self) -> Result<Option<ExfatDirEntrySet>> {
        loop {
            if self.offset + EXFAT_ENTRY_SIZE > self.data.len() {
                return Ok(None);
            }
            let etype = self.data[self.offset];
            if etype == entry_type::END_OF_DIR {
                return Ok(None);
            }
            // Skip non-FILE primaries and deleted entries (bit 6 clear).
            if etype != entry_type::FILE {
                self.offset += EXFAT_ENTRY_SIZE;
                continue;
            }

            let file_entry = ExfatFileEntry::from_bytes(&self.data[self.offset..])?;
            let secondary_count = file_entry.secondary_count as usize;
            self.offset += EXFAT_ENTRY_SIZE;

            if secondary_count < 2 {
                continue; // Need at least STREAM_EXT + 1 FILE_NAME.
            }

            if self.offset + secondary_count * EXFAT_ENTRY_SIZE > self.data.len() {
                return Err(Error::InvalidArgument);
            }

            // Second entry must be STREAM_EXTENSION.
            let stream = ExfatStreamExt::from_bytes(&self.data[self.offset..])?;
            self.offset += EXFAT_ENTRY_SIZE;

            let name_entry_count = secondary_count - 1;
            let mut entry_set = ExfatDirEntrySet {
                file_entry,
                stream,
                ..ExfatDirEntrySet::default()
            };

            let mut pos = 0usize;
            for _ in 0..name_entry_count {
                if self.offset + EXFAT_ENTRY_SIZE > self.data.len() {
                    return Err(Error::InvalidArgument);
                }
                if self.data[self.offset] != entry_type::FILE_NAME {
                    self.offset += EXFAT_ENTRY_SIZE;
                    continue;
                }
                let name_entry = ExfatFileName::from_bytes(&self.data[self.offset..])?;
                self.offset += EXFAT_ENTRY_SIZE;
                for &ch in name_entry.name.iter() {
                    if ch == 0 {
                        break;
                    }
                    if pos < 255 {
                        entry_set.name[pos] = ch;
                        pos += 1;
                    }
                }
            }
            entry_set.name_len = pos;
            return Ok(Some(entry_set));
        }
    }
}
