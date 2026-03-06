// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VFAT (FAT32 with long file name) directory operations.
//!
//! Implements directory iteration, creation, and removal for VFAT filesystems.
//! VFAT extends FAT32 with Long File Name (LFN) entries using the VFAT
//! extension, allowing filenames up to 255 UTF-16 characters.
//!
//! # LFN Structure
//!
//! Long filenames are stored as a sequence of LFN directory entries
//! preceding the corresponding short-name (8.3) entry. Each LFN entry
//! holds 13 UTF-16 code units. Entries are stored in reverse order with
//! sequence numbers and a checksum over the short name.

use oncrix_lib::{Error, Result};

/// Maximum number of LFN entries per filename (ceil(255 / 13)).
pub const LFN_MAX_ENTRIES: usize = 20;

/// Number of UTF-16 characters stored per LFN directory entry.
pub const LFN_CHARS_PER_ENTRY: usize = 13;

/// Size of a raw FAT directory entry in bytes.
pub const DIR_ENTRY_SIZE: usize = 32;

/// Attribute byte for LFN entries (ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID).
pub const LFN_ATTR: u8 = 0x0F;

/// First byte of a deleted directory entry.
pub const DELETED_MARKER: u8 = 0xE5;

/// First byte indicating the end of the directory.
pub const EOD_MARKER: u8 = 0x00;

/// A raw 32-byte FAT directory entry.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct RawDirEntry {
    /// Short name (8 bytes name + 3 bytes extension).
    pub name: [u8; 11],
    /// File attributes.
    pub attr: u8,
    /// Reserved / NT flags.
    pub nt_flags: u8,
    /// Creation time (hundredths of a second).
    pub crt_time_tenth: u8,
    /// Creation time (2-second resolution).
    pub crt_time: u16,
    /// Creation date.
    pub crt_date: u16,
    /// Last access date.
    pub acc_date: u16,
    /// High 16 bits of first cluster (FAT32).
    pub fst_clus_hi: u16,
    /// Write time.
    pub wrt_time: u16,
    /// Write date.
    pub wrt_date: u16,
    /// Low 16 bits of first cluster.
    pub fst_clus_lo: u16,
    /// File size in bytes.
    pub file_size: u32,
}

impl Default for RawDirEntry {
    fn default() -> Self {
        Self {
            name: [0x20; 11],
            attr: 0,
            nt_flags: 0,
            crt_time_tenth: 0,
            crt_time: 0,
            crt_date: 0,
            acc_date: 0,
            fst_clus_hi: 0,
            wrt_time: 0,
            wrt_date: 0,
            fst_clus_lo: 0,
            file_size: 0,
        }
    }
}

impl RawDirEntry {
    /// Returns `true` if this entry is a long-filename entry.
    pub const fn is_lfn(&self) -> bool {
        self.attr == LFN_ATTR
    }

    /// Returns `true` if this entry is the end-of-directory marker.
    pub const fn is_eod(&self) -> bool {
        self.name[0] == EOD_MARKER
    }

    /// Returns `true` if this entry has been deleted.
    pub const fn is_deleted(&self) -> bool {
        self.name[0] == DELETED_MARKER
    }

    /// Returns `true` if this is a regular file or directory entry (not LFN).
    pub const fn is_regular(&self) -> bool {
        !self.is_lfn() && !self.is_eod() && !self.is_deleted()
    }

    /// Returns the first cluster number (FAT32 full 32-bit).
    pub const fn first_cluster(&self) -> u32 {
        ((self.fst_clus_hi as u32) << 16) | (self.fst_clus_lo as u32)
    }
}

/// A raw LFN (Long File Name) directory entry.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct LfnEntry {
    /// Sequence number (1-based) with 0x40 OR'd into the last entry.
    pub order: u8,
    /// Characters 1-5 (UTF-16LE).
    pub name1: [u16; 5],
    /// Attributes (always 0x0F).
    pub attr: u8,
    /// Type (always 0).
    pub lfn_type: u8,
    /// Checksum of the short-name entry.
    pub checksum: u8,
    /// Characters 6-11 (UTF-16LE).
    pub name2: [u16; 6],
    /// First cluster (always 0).
    pub fst_clus: u16,
    /// Characters 12-13 (UTF-16LE).
    pub name3: [u16; 2],
}

impl Default for LfnEntry {
    fn default() -> Self {
        Self {
            order: 0,
            name1: [0; 5],
            attr: LFN_ATTR,
            lfn_type: 0,
            checksum: 0,
            name2: [0; 6],
            fst_clus: 0,
            name3: [0; 2],
        }
    }
}

impl LfnEntry {
    /// Extracts the 13 UTF-16 code units from this LFN entry into `buf`.
    pub fn chars(&self, buf: &mut [u16; LFN_CHARS_PER_ENTRY]) {
        buf[..5].copy_from_slice(&self.name1);
        buf[5..11].copy_from_slice(&self.name2);
        buf[11..13].copy_from_slice(&self.name3);
    }
}

/// Decoded VFAT directory entry with reconstructed long name.
pub struct VfatDirEntry {
    /// Short-name (8.3) representation (space-padded, no dot).
    pub short_name: [u8; 11],
    /// Long filename as UTF-16LE code units (null-terminated if < 255 chars).
    pub long_name: [u16; 256],
    /// Number of valid code units in `long_name` (excluding null terminator).
    pub long_name_len: usize,
    /// First cluster of the file data.
    pub first_cluster: u32,
    /// File size in bytes (0 for directories).
    pub file_size: u32,
    /// File attributes.
    pub attr: u8,
}

impl Default for VfatDirEntry {
    fn default() -> Self {
        Self {
            short_name: [0x20; 11],
            long_name: [0u16; 256],
            long_name_len: 0,
            first_cluster: 0,
            file_size: 0,
            attr: 0,
        }
    }
}

impl VfatDirEntry {
    /// Returns `true` if the attribute indicates a subdirectory.
    pub const fn is_dir(&self) -> bool {
        self.attr & 0x10 != 0
    }

    /// Returns `true` if the attribute indicates a read-only entry.
    pub const fn is_read_only(&self) -> bool {
        self.attr & 0x01 != 0
    }
}

/// Compute the LFN checksum over an 8.3 short name.
///
/// The algorithm is specified by the Microsoft FAT specification:
/// rotate-right 1 bit and add the next byte, for all 11 bytes.
pub fn lfn_checksum(short_name: &[u8; 11]) -> u8 {
    let mut sum: u8 = 0;
    for &byte in short_name.iter() {
        sum = (sum >> 1) | (sum << 7);
        sum = sum.wrapping_add(byte);
    }
    sum
}

/// Iterator state for walking a VFAT directory cluster chain.
pub struct VfatDirIter<'a> {
    /// Raw directory data (one or more 512-byte sectors).
    data: &'a [u8],
    /// Current byte offset within `data`.
    offset: usize,
    /// Accumulated LFN entries (stored in reverse order during parsing).
    lfn_buf: [LfnEntry; LFN_MAX_ENTRIES],
    /// Number of valid LFN entries buffered.
    lfn_count: usize,
}

impl<'a> VfatDirIter<'a> {
    /// Creates a new directory iterator over `data`.
    pub const fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            offset: 0,
            lfn_buf: [LfnEntry {
                order: 0,
                name1: [0; 5],
                attr: LFN_ATTR,
                lfn_type: 0,
                checksum: 0,
                name2: [0; 6],
                fst_clus: 0,
                name3: [0; 2],
            }; LFN_MAX_ENTRIES],
            lfn_count: 0,
        }
    }

    /// Reads the next decoded `VfatDirEntry`, or `None` at end-of-directory.
    ///
    /// Returns `Err` if the data is malformed or a checksum mismatch is detected.
    pub fn next_entry(&mut self) -> Result<Option<VfatDirEntry>> {
        loop {
            if self.offset + DIR_ENTRY_SIZE > self.data.len() {
                return Ok(None);
            }

            // SAFETY: We verified the slice bounds above.
            let raw_bytes = &self.data[self.offset..self.offset + DIR_ENTRY_SIZE];
            self.offset += DIR_ENTRY_SIZE;

            if raw_bytes[0] == EOD_MARKER {
                return Ok(None);
            }
            if raw_bytes[0] == DELETED_MARKER {
                self.lfn_count = 0;
                continue;
            }

            let attr = raw_bytes[11];

            if attr == LFN_ATTR {
                // Parse LFN entry.
                if self.lfn_count >= LFN_MAX_ENTRIES {
                    return Err(Error::InvalidArgument);
                }
                let mut lfn = LfnEntry::default();
                lfn.order = raw_bytes[0];
                for (i, chunk) in raw_bytes[1..11].chunks_exact(2).enumerate() {
                    lfn.name1[i] = u16::from_le_bytes([chunk[0], chunk[1]]);
                }
                lfn.attr = raw_bytes[11];
                lfn.lfn_type = raw_bytes[12];
                lfn.checksum = raw_bytes[13];
                for (i, chunk) in raw_bytes[14..26].chunks_exact(2).enumerate() {
                    lfn.name2[i] = u16::from_le_bytes([chunk[0], chunk[1]]);
                }
                lfn.fst_clus = u16::from_le_bytes([raw_bytes[26], raw_bytes[27]]);
                for (i, chunk) in raw_bytes[28..32].chunks_exact(2).enumerate() {
                    lfn.name3[i] = u16::from_le_bytes([chunk[0], chunk[1]]);
                }
                // Store in reverse order (last LFN entry encountered first).
                self.lfn_buf[self.lfn_count] = lfn;
                self.lfn_count += 1;
                continue;
            }

            // Short-name (8.3) entry.
            let mut raw = RawDirEntry::default();
            raw.name.copy_from_slice(&raw_bytes[0..11]);
            raw.attr = attr;
            raw.nt_flags = raw_bytes[12];
            raw.crt_time_tenth = raw_bytes[13];
            raw.crt_time = u16::from_le_bytes([raw_bytes[14], raw_bytes[15]]);
            raw.crt_date = u16::from_le_bytes([raw_bytes[16], raw_bytes[17]]);
            raw.acc_date = u16::from_le_bytes([raw_bytes[18], raw_bytes[19]]);
            raw.fst_clus_hi = u16::from_le_bytes([raw_bytes[20], raw_bytes[21]]);
            raw.wrt_time = u16::from_le_bytes([raw_bytes[22], raw_bytes[23]]);
            raw.wrt_date = u16::from_le_bytes([raw_bytes[24], raw_bytes[25]]);
            raw.fst_clus_lo = u16::from_le_bytes([raw_bytes[26], raw_bytes[27]]);
            raw.file_size =
                u32::from_le_bytes([raw_bytes[28], raw_bytes[29], raw_bytes[30], raw_bytes[31]]);

            let mut entry = VfatDirEntry {
                short_name: raw.name,
                long_name: [0u16; 256],
                long_name_len: 0,
                first_cluster: raw.first_cluster(),
                file_size: raw.file_size,
                attr: raw.attr,
            };

            if self.lfn_count > 0 {
                // Validate checksum.
                let expected_cksum = lfn_checksum(&raw.name);
                if self.lfn_buf[0].checksum != expected_cksum {
                    self.lfn_count = 0;
                    return Err(Error::IoError);
                }

                // Reassemble long name (LFN entries are stored in reverse).
                let mut pos = 0usize;
                for i in (0..self.lfn_count).rev() {
                    let mut chars = [0u16; LFN_CHARS_PER_ENTRY];
                    self.lfn_buf[i].chars(&mut chars);
                    for &ch in chars.iter() {
                        if ch == 0x0000 || ch == 0xFFFF {
                            break;
                        }
                        if pos < 255 {
                            entry.long_name[pos] = ch;
                            pos += 1;
                        }
                    }
                }
                entry.long_name_len = pos;
                self.lfn_count = 0;
            }

            return Ok(Some(entry));
        }
    }
}

/// Formats an 8.3 short name into the canonical `NAME.EXT` representation.
///
/// Trailing spaces are stripped. The dot is omitted if the extension is empty.
/// The output is written into `buf` and the number of bytes written is returned.
pub fn format_short_name(name: &[u8; 11], buf: &mut [u8; 13]) -> usize {
    let name_part = &name[0..8];
    let ext_part = &name[8..11];

    let name_len = name_part
        .iter()
        .rposition(|&b| b != b' ')
        .map_or(0, |i| i + 1);
    let ext_len = ext_part
        .iter()
        .rposition(|&b| b != b' ')
        .map_or(0, |i| i + 1);

    let mut pos = 0;
    for i in 0..name_len {
        buf[pos] = name_part[i];
        pos += 1;
    }
    if ext_len > 0 {
        buf[pos] = b'.';
        pos += 1;
        for i in 0..ext_len {
            buf[pos] = ext_part[i];
            pos += 1;
        }
    }
    pos
}
