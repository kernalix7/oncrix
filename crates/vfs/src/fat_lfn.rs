// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! FAT Long File Name (LFN) support.
//!
//! Microsoft's VFAT extension stores long file names as a sequence of
//! special directory entries that precede the 8.3 short-name entry.
//! Each LFN entry holds 13 UTF-16LE code units.  This module implements
//! parsing, assembly, and checksum validation for LFN entries.

use oncrix_lib::{Error, Result};

/// Maximum number of LFN directory entries for one filename.
pub const LFN_MAX_ENTRIES: usize = 20;
/// Code units per LFN entry (5 + 6 + 2 = 13).
pub const LFN_CHARS_PER_ENTRY: usize = 13;
/// Maximum filename length in UTF-16LE code units.
pub const LFN_MAX_LEN: usize = LFN_MAX_ENTRIES * LFN_CHARS_PER_ENTRY; // 260

/// LFN directory entry attribute byte (always 0x0F).
pub const LFN_ATTR: u8 = 0x0F;
/// Last-entry flag in the sequence ordinal byte.
pub const LFN_LAST_ENTRY_FLAG: u8 = 0x40;

/// A single VFAT LFN directory entry (32 bytes).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct LfnEntry {
    /// Sequence number (1-based).  Bit 6 set = last entry in the sequence.
    pub ordinal: u8,
    /// Name chars 1-5 (UTF-16LE, 0x0000 = end, 0xFFFF = unused).
    pub name1: [u16; 5],
    /// Attributes — must be `LFN_ATTR`.
    pub attr: u8,
    /// Reserved (must be 0).
    pub reserved: u8,
    /// Checksum of the 8.3 short-name entry.
    pub checksum: u8,
    /// Name chars 6-11.
    pub name2: [u16; 6],
    /// Cluster (must be 0).
    pub cluster_lo: u16,
    /// Name chars 12-13.
    pub name3: [u16; 2],
}

impl LfnEntry {
    /// Sequence number without the last-entry flag.
    pub fn seq_num(&self) -> u8 {
        self.ordinal & !LFN_LAST_ENTRY_FLAG
    }

    /// Whether this is the last (highest-ordinal) entry.
    pub fn is_last(&self) -> bool {
        self.ordinal & LFN_LAST_ENTRY_FLAG != 0
    }

    /// Whether this entry is erased.
    pub fn is_erased(&self) -> bool {
        self.ordinal == 0xe5
    }

    /// Collect the 13 UTF-16LE code units from this entry.
    pub fn collect_chars(&self, out: &mut [u16; LFN_CHARS_PER_ENTRY]) {
        out[0..5].copy_from_slice(&self.name1);
        out[5..11].copy_from_slice(&self.name2);
        out[11..13].copy_from_slice(&self.name3);
    }
}

/// Compute the LFN checksum of an 8.3 short-name (11 bytes, uppercase).
pub fn lfn_checksum(short_name: &[u8; 11]) -> u8 {
    let mut sum: u8 = 0;
    for &b in short_name {
        sum = sum.rotate_right(1).wrapping_add(b);
    }
    sum
}

/// Assemble a long filename from a sequence of LFN entries.
///
/// `entries` must be in reverse order (lowest ordinal last), as they appear
/// in a directory scan reading backward.  Returns the UTF-16LE string length.
pub fn assemble_lfn(
    entries: &[LfnEntry],
    out: &mut [u16; LFN_MAX_LEN],
    checksum: u8,
) -> Result<usize> {
    if entries.is_empty() {
        return Err(Error::InvalidArgument);
    }
    let mut total = 0usize;
    // Entries arrive in reverse ordinal order (highest-ordinal first from disk).
    let entry_count = entries.len();
    for (i, entry) in entries.iter().enumerate() {
        if entry.checksum != checksum {
            return Err(Error::InvalidArgument);
        }
        let expected_seq = (entry_count - i) as u8;
        if entry.seq_num() != expected_seq {
            return Err(Error::InvalidArgument);
        }
        let offset = (expected_seq as usize - 1) * LFN_CHARS_PER_ENTRY;
        if offset + LFN_CHARS_PER_ENTRY > LFN_MAX_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut chars = [0u16; LFN_CHARS_PER_ENTRY];
        entry.collect_chars(&mut chars);
        // Find actual character count (up to first 0x0000).
        let valid = chars
            .iter()
            .position(|&c| c == 0x0000)
            .unwrap_or(LFN_CHARS_PER_ENTRY);
        out[offset..offset + valid].copy_from_slice(&chars[..valid]);
        if offset + valid > total {
            total = offset + valid;
        }
    }
    Ok(total)
}

/// Convert a UTF-16LE slice to a UTF-8 byte array (BMP only, no surrogates).
pub fn utf16_to_utf8(src: &[u16], dst: &mut [u8]) -> Result<usize> {
    let mut off = 0usize;
    for &ch in src {
        if ch == 0 {
            break;
        }
        if ch < 0x80 {
            if off >= dst.len() {
                return Err(Error::InvalidArgument);
            }
            dst[off] = ch as u8;
            off += 1;
        } else if ch < 0x800 {
            if off + 1 >= dst.len() {
                return Err(Error::InvalidArgument);
            }
            dst[off] = 0xc0 | ((ch >> 6) as u8);
            dst[off + 1] = 0x80 | ((ch & 0x3f) as u8);
            off += 2;
        } else {
            if off + 2 >= dst.len() {
                return Err(Error::InvalidArgument);
            }
            dst[off] = 0xe0 | ((ch >> 12) as u8);
            dst[off + 1] = 0x80 | (((ch >> 6) & 0x3f) as u8);
            dst[off + 2] = 0x80 | ((ch & 0x3f) as u8);
            off += 3;
        }
    }
    Ok(off)
}

/// Build a sequence of LFN entries for a given UTF-16LE filename.
///
/// `short_name` is the 8.3 name used to compute the checksum.
/// Returns the number of entries written into `out` (entries are in
/// directory order: highest ordinal first).
pub fn build_lfn_entries(
    name: &[u16],
    short_name: &[u8; 11],
    out: &mut [LfnEntry; LFN_MAX_ENTRIES],
) -> Result<usize> {
    if name.is_empty() || name.len() > LFN_MAX_LEN {
        return Err(Error::InvalidArgument);
    }
    let checksum = lfn_checksum(short_name);
    let entry_count = (name.len() + LFN_CHARS_PER_ENTRY - 1) / LFN_CHARS_PER_ENTRY;
    if entry_count > LFN_MAX_ENTRIES {
        return Err(Error::InvalidArgument);
    }
    for i in 0..entry_count {
        let seq = (i + 1) as u8;
        let is_last = i + 1 == entry_count;
        let offset = i * LFN_CHARS_PER_ENTRY;
        let mut name1 = [0xffffu16; 5];
        let mut name2 = [0xffffu16; 6];
        let mut name3 = [0xffffu16; 2];
        let chunk_end = (offset + LFN_CHARS_PER_ENTRY).min(name.len());
        let chunk = &name[offset..chunk_end];
        // Fill name fields.
        for (j, &cu) in chunk.iter().enumerate() {
            let is_terminator = j == chunk.len() && chunk.len() < LFN_CHARS_PER_ENTRY;
            let val = if is_terminator { 0x0000 } else { cu };
            if j < 5 {
                name1[j] = val;
            } else if j < 11 {
                name2[j - 5] = val;
            } else {
                name3[j - 11] = val;
            }
        }
        // Mark end of filename within the last entry.
        if is_last && chunk.len() < LFN_CHARS_PER_ENTRY {
            let term_pos = chunk.len();
            if term_pos < 5 {
                name1[term_pos] = 0x0000;
            } else if term_pos < 11 {
                name2[term_pos - 5] = 0x0000;
            } else {
                name3[term_pos - 11] = 0x0000;
            }
        }
        let ordinal = if is_last {
            seq | LFN_LAST_ENTRY_FLAG
        } else {
            seq
        };
        // Store in reverse order (highest ordinal at index 0).
        let out_idx = entry_count - 1 - i;
        out[out_idx] = LfnEntry {
            ordinal,
            name1,
            attr: LFN_ATTR,
            reserved: 0,
            checksum,
            name2,
            cluster_lo: 0,
            name3,
        };
    }
    Ok(entry_count)
}
