// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ISO 9660 (CD-ROM) directory record parsing and iteration.
//!
//! ISO 9660 is the standard filesystem for optical media. This module
//! implements directory record parsing according to ECMA-119 (ISO 9660:1988).
//!
//! # Layout
//!
//! Each directory record has a variable length. The first byte is the
//! record length; a zero length byte indicates end-of-sector padding.
//! Directories are stored in logical blocks of 2048 bytes.
//!
//! # Joliet Extension
//!
//! Joliet directories use UCS-2 BE filenames up to 64 characters (128 bytes).
//! The Joliet volume descriptor is identified by escape sequences in the
//! Supplementary Volume Descriptor.

use oncrix_lib::{Error, Result};

/// Logical block size for ISO 9660 (always 2048 bytes).
pub const ISO_BLOCK_SIZE: usize = 2048;

/// Offset of the directory record length field.
const DR_LEN_OFF: usize = 0;
/// Offset of the extended attribute record length field.
const DR_EAR_OFF: usize = 1;
/// Offset of the location of extent (little-endian u32).
const DR_EXTENT_LBA_OFF: usize = 2;
/// Offset of the data length (little-endian u32).
const DR_DATA_LEN_OFF: usize = 10;
/// Offset of the file flags byte.
const DR_FLAGS_OFF: usize = 25;
/// Offset of the file unit size (interleaved files).
const DR_FILE_UNIT_SIZE_OFF: usize = 26;
/// Offset of the interleave gap size.
const DR_INTERLEAVE_GAP_OFF: usize = 27;
/// Offset of the volume sequence number (little-endian u16).
const DR_VOL_SEQ_OFF: usize = 28;
/// Offset of the file identifier length.
const DR_ID_LEN_OFF: usize = 32;
/// Offset where the file identifier begins.
const DR_ID_OFF: usize = 33;
/// Minimum length of a directory record.
const DR_MIN_LEN: usize = 33;

/// File flag bits in ISO 9660 directory records.
pub mod flags {
    /// Entry is hidden.
    pub const HIDDEN: u8 = 0x01;
    /// Entry is a directory.
    pub const DIRECTORY: u8 = 0x02;
    /// Entry is an associated file.
    pub const ASSOCIATED: u8 = 0x04;
    /// Extended attribute record contains extended information about the format.
    pub const RECORD: u8 = 0x08;
    /// Owner and group identification are specified in the extended attribute record.
    pub const PROTECTION: u8 = 0x10;
    /// File has more than one directory record (multi-extent).
    pub const MULTI_EXTENT: u8 = 0x80;
}

/// A parsed ISO 9660 directory record.
pub struct IsoDirRecord {
    /// Length of the directory record (includes identifier).
    pub record_len: u8,
    /// Starting LBA of the file extent.
    pub extent_lba: u32,
    /// Size of the file extent in bytes.
    pub data_len: u32,
    /// File flags (see [`flags`]).
    pub file_flags: u8,
    /// File identifier (name), raw bytes.
    pub identifier: [u8; 222],
    /// Length of the identifier in bytes.
    pub identifier_len: u8,
}

impl Default for IsoDirRecord {
    fn default() -> Self {
        Self {
            record_len: 0,
            extent_lba: 0,
            data_len: 0,
            file_flags: 0,
            identifier: [0u8; 222],
            identifier_len: 0,
        }
    }
}

impl IsoDirRecord {
    /// Returns `true` if this record represents a directory.
    pub const fn is_dir(&self) -> bool {
        self.file_flags & flags::DIRECTORY != 0
    }

    /// Returns `true` if this is a hidden entry.
    pub const fn is_hidden(&self) -> bool {
        self.file_flags & flags::HIDDEN != 0
    }

    /// Returns `true` if this is the current directory (`.`) pseudo-entry.
    pub fn is_dot(&self) -> bool {
        self.identifier_len == 1 && self.identifier[0] == 0x00
    }

    /// Returns `true` if this is the parent directory (`..`) pseudo-entry.
    pub fn is_dotdot(&self) -> bool {
        self.identifier_len == 1 && self.identifier[0] == 0x01
    }

    /// Returns the raw filename bytes, excluding version suffix (`;1`).
    pub fn name_bytes(&self) -> &[u8] {
        let id = &self.identifier[..self.identifier_len as usize];
        // Strip version suffix `;N` if present.
        if let Some(pos) = id.iter().rposition(|&b| b == b';') {
            &id[..pos]
        } else {
            id
        }
    }

    /// Returns the raw filename bytes without trailing dot (for files with no extension).
    pub fn name_bytes_clean(&self) -> &[u8] {
        let name = self.name_bytes();
        // ISO 9660 level 1 appends a trailing dot for files with no extension.
        if name.last() == Some(&b'.') {
            &name[..name.len() - 1]
        } else {
            name
        }
    }
}

/// Parse a single directory record from `data` starting at `offset`.
///
/// Returns `None` if the record length is zero (end-of-sector padding)
/// or if there is insufficient data.
pub fn parse_record(data: &[u8], offset: usize) -> Result<Option<IsoDirRecord>> {
    if offset >= data.len() {
        return Ok(None);
    }

    let record_len = data[offset + DR_LEN_OFF] as usize;
    if record_len == 0 {
        return Ok(None);
    }
    if record_len < DR_MIN_LEN || offset + record_len > data.len() {
        return Err(Error::InvalidArgument);
    }

    let raw = &data[offset..offset + record_len];

    let extent_lba = u32::from_le_bytes([
        raw[DR_EXTENT_LBA_OFF],
        raw[DR_EXTENT_LBA_OFF + 1],
        raw[DR_EXTENT_LBA_OFF + 2],
        raw[DR_EXTENT_LBA_OFF + 3],
    ]);
    let data_len = u32::from_le_bytes([
        raw[DR_DATA_LEN_OFF],
        raw[DR_DATA_LEN_OFF + 1],
        raw[DR_DATA_LEN_OFF + 2],
        raw[DR_DATA_LEN_OFF + 3],
    ]);
    let file_flags = raw[DR_FLAGS_OFF];
    let id_len = raw[DR_ID_LEN_OFF];

    if DR_ID_OFF + (id_len as usize) > record_len {
        return Err(Error::InvalidArgument);
    }

    let mut rec = IsoDirRecord {
        record_len: record_len as u8,
        extent_lba,
        data_len,
        file_flags,
        identifier: [0u8; 222],
        identifier_len: id_len,
    };
    let copy_len = (id_len as usize).min(222);
    rec.identifier[..copy_len].copy_from_slice(&raw[DR_ID_OFF..DR_ID_OFF + copy_len]);

    Ok(Some(rec))
}

/// Iterator over ISO 9660 directory records within a single logical block.
pub struct IsoDirIter<'a> {
    /// Raw block data (2048 bytes expected).
    data: &'a [u8],
    /// Current byte offset within `data`.
    offset: usize,
}

impl<'a> IsoDirIter<'a> {
    /// Creates a new iterator starting at the beginning of `data`.
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    /// Returns the next directory record.
    ///
    /// Skips zero-length padding bytes at end of sector.
    pub fn next_record(&mut self) -> Result<Option<IsoDirRecord>> {
        loop {
            if self.offset >= self.data.len() {
                return Ok(None);
            }
            // Skip sector-padding zero bytes.
            if self.data[self.offset] == 0 {
                // Advance to next 2048-byte boundary.
                self.offset = (self.offset / ISO_BLOCK_SIZE + 1) * ISO_BLOCK_SIZE;
                return Ok(None);
            }

            let rec = parse_record(self.data, self.offset)?;
            match rec {
                None => return Ok(None),
                Some(r) => {
                    self.offset += r.record_len as usize;
                    // Even-align: each record starts on an even byte boundary.
                    if self.offset % 2 != 0 {
                        self.offset += 1;
                    }
                    return Ok(Some(r));
                }
            }
        }
    }
}

/// Joliet long filename decoder (UCS-2 Big Endian to UTF-16 LE buffer).
///
/// Joliet filenames are stored as UCS-2 BE. This converts them into a
/// local UTF-16 LE buffer for further processing.
pub fn decode_joliet_name(raw: &[u8], out: &mut [u16; 128]) -> usize {
    let pairs = raw.len() / 2;
    let count = pairs.min(128);
    for i in 0..count {
        out[i] = u16::from_be_bytes([raw[i * 2], raw[i * 2 + 1]]);
    }
    count
}
