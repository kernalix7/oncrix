// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! FAT32 long filename (LFN) support.
//!
//! Long filenames in FAT32 (VFAT) are stored in a sequence of LFN directory
//! entries that precede the corresponding 8.3 short-name entry. Each LFN
//! entry stores 13 UCS-2 characters across three fields.
//!
//! # Design
//!
//! - [`LfnEntry`] — on-disk LFN directory entry layout
//! - [`encode_lfn`] — encode a UTF-8 name into LFN entries
//! - [`decode_lfn`] — decode a sequence of LFN entries into a UTF-8 name
//! - [`generate_short_name`] — generate 8.3 short name with `~N` suffix
//! - Short name checksum for LFN entry validation
//!
//! # References
//!
//! - Microsoft FAT32 File System Specification (December 2000)
//! - Linux `fs/fat/dir.c`, `fs/fat/namei_vfat.c`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum LFN entries per name (255 chars / 13 chars per entry = 20 entries).
pub const MAX_LFN_ENTRIES: usize = 20;

/// Characters per LFN entry.
pub const LFN_CHARS_PER_ENTRY: usize = 13;

/// Maximum UTF-8 LFN length in bytes.
pub const MAX_LFN_LEN: usize = 255;

/// Attribute byte for LFN entries.
pub const LFN_ATTR: u8 = 0x0F;

/// Short name length (8+3).
pub const SHORT_NAME_LEN: usize = 11;

/// Last LFN entry marker.
pub const LFN_LAST_LONG_ENTRY: u8 = 0x40;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// On-disk representation of an LFN directory entry (32 bytes).
#[derive(Debug, Clone, Copy, Default)]
pub struct LfnEntry {
    /// Sequence number (1-based; OR'd with 0x40 for last entry).
    pub sequence: u8,
    /// First 5 UCS-2 characters.
    pub name1: [u16; 5],
    /// Attribute field (always 0x0F for LFN).
    pub attr: u8,
    /// Reserved (type, always 0).
    pub entry_type: u8,
    /// Checksum of the 8.3 short name.
    pub checksum: u8,
    /// Next 6 UCS-2 characters.
    pub name2: [u16; 6],
    /// Reserved (cluster, always 0).
    pub cluster: u16,
    /// Final 2 UCS-2 characters.
    pub name3: [u16; 2],
}

impl LfnEntry {
    /// Extract all 13 UCS-2 code units from this entry.
    pub fn ucs2_chars(&self) -> [u16; LFN_CHARS_PER_ENTRY] {
        let mut out = [0u16; LFN_CHARS_PER_ENTRY];
        out[..5].copy_from_slice(&self.name1);
        out[5..11].copy_from_slice(&self.name2);
        out[11..13].copy_from_slice(&self.name3);
        out
    }

    /// Set the 13 UCS-2 code units for this entry.
    pub fn set_ucs2_chars(&mut self, chars: &[u16; LFN_CHARS_PER_ENTRY]) {
        self.name1.copy_from_slice(&chars[..5]);
        self.name2.copy_from_slice(&chars[5..11]);
        self.name3.copy_from_slice(&chars[11..13]);
    }
}

/// Encoded LFN: up to 20 LFN entries + the 8.3 short name.
#[derive(Default)]
pub struct EncodedLfn {
    /// LFN entries in on-disk order (first is highest-numbered).
    pub entries: [LfnEntry; MAX_LFN_ENTRIES],
    /// Number of LFN entries.
    pub entry_count: usize,
    /// 8.3 short name (11 bytes, space-padded).
    pub short_name: [u8; SHORT_NAME_LEN],
}

// ---------------------------------------------------------------------------
// Checksum helpers
// ---------------------------------------------------------------------------

/// Compute the 8.3 short-name checksum as defined by Microsoft.
pub fn short_name_checksum(short_name: &[u8; SHORT_NAME_LEN]) -> u8 {
    let mut sum: u8 = 0;
    for &b in short_name.iter() {
        sum = (sum >> 1).wrapping_add(sum << 7).wrapping_add(b);
    }
    sum
}

// ---------------------------------------------------------------------------
// UCS-2 / UTF-8 helpers
// ---------------------------------------------------------------------------

/// Encode a single Unicode code point to UCS-2 (BMP only).
fn char_to_ucs2(c: char) -> u16 {
    let cp = c as u32;
    if cp <= 0xFFFF { cp as u16 } else { b'?' as u16 }
}

/// Decode a single UCS-2 code unit to a char (ASCII / Latin extension).
fn ucs2_to_char(v: u16) -> char {
    if v == 0xFFFF || v == 0 {
        '\0'
    } else {
        char::from_u32(v as u32).unwrap_or('?')
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Encode a UTF-8 filename into a sequence of LFN directory entries plus an
/// 8.3 short name.
///
/// `name` must be ≤ 255 bytes. The resulting `EncodedLfn` entries are in
/// reverse sequence order (last LFN entry first = on-disk before 8.3 entry).
pub fn encode_lfn(name: &[u8], short_name: &[u8; SHORT_NAME_LEN]) -> Result<EncodedLfn> {
    if name.is_empty() || name.len() > MAX_LFN_LEN {
        return Err(Error::InvalidArgument);
    }

    // Convert UTF-8 to UCS-2 characters.
    let mut ucs2_buf = [0u16; MAX_LFN_LEN + 1];
    let mut ucs2_len = 0;

    let s = core::str::from_utf8(name).map_err(|_| Error::InvalidArgument)?;
    for c in s.chars() {
        if ucs2_len >= MAX_LFN_LEN {
            return Err(Error::InvalidArgument);
        }
        ucs2_buf[ucs2_len] = char_to_ucs2(c);
        ucs2_len += 1;
    }
    // NUL terminator.
    if ucs2_len < MAX_LFN_LEN + 1 {
        ucs2_buf[ucs2_len] = 0;
    }

    let checksum = short_name_checksum(short_name);
    let entry_count = (ucs2_len + LFN_CHARS_PER_ENTRY - 1) / LFN_CHARS_PER_ENTRY;
    if entry_count > MAX_LFN_ENTRIES {
        return Err(Error::InvalidArgument);
    }

    let mut out = EncodedLfn::default();
    out.short_name = *short_name;
    out.entry_count = entry_count;

    for seq in 0..entry_count {
        let mut entry = LfnEntry {
            sequence: (seq + 1) as u8,
            attr: LFN_ATTR,
            checksum,
            ..LfnEntry::default()
        };
        if seq == entry_count - 1 {
            entry.sequence |= LFN_LAST_LONG_ENTRY;
        }
        let char_start = seq * LFN_CHARS_PER_ENTRY;
        let mut chars = [0xFFFFu16; LFN_CHARS_PER_ENTRY];
        for j in 0..LFN_CHARS_PER_ENTRY {
            let idx = char_start + j;
            if idx < ucs2_len {
                chars[j] = ucs2_buf[idx];
            } else if idx == ucs2_len {
                chars[j] = 0x0000; // NUL terminator
            }
            // Remaining are 0xFFFF (padding).
        }
        entry.set_ucs2_chars(&chars);
        // Store entries in reverse order (last seq first).
        out.entries[entry_count - 1 - seq] = entry;
    }
    Ok(out)
}

/// Decode a sequence of LFN entries into a UTF-8 byte string.
///
/// `entries` must be in on-disk order (last LFN entry = entries[0]).
/// Writes the decoded name into `out`. Returns the length written.
pub fn decode_lfn(entries: &[LfnEntry], out: &mut [u8]) -> Result<usize> {
    if entries.is_empty() {
        return Err(Error::InvalidArgument);
    }

    // Collect UCS-2 characters in order (from highest-numbered entry backwards).
    let mut ucs2_buf = [0u16; MAX_LFN_LEN + 1];
    let mut ucs2_len = 0;

    // entries[0] is the entry with the highest sequence number (= last in the file).
    // We iterate in reverse to build the name front-to-back.
    for i in (0..entries.len()).rev() {
        let chars = entries[i].ucs2_chars();
        for &c in chars.iter() {
            if c == 0x0000 || c == 0xFFFF {
                break;
            }
            if ucs2_len < MAX_LFN_LEN {
                ucs2_buf[ucs2_len] = c;
                ucs2_len += 1;
            }
        }
    }

    // Encode UCS-2 to UTF-8 (ASCII only for simplicity; full BMP for non-ASCII).
    let mut pos = 0;
    for i in 0..ucs2_len {
        let ch = ucs2_to_char(ucs2_buf[i]);
        if ch == '\0' {
            break;
        }
        let mut buf = [0u8; 4];
        let s = ch.encode_utf8(&mut buf);
        for &b in s.as_bytes() {
            if pos >= out.len() {
                return Err(Error::InvalidArgument);
            }
            out[pos] = b;
            pos += 1;
        }
    }
    Ok(pos)
}

/// Generate an 8.3 short name from a long name.
///
/// Implements the `~N` numeric tail extension to avoid collisions.
/// `n` is the numeric suffix (1..=999999).
///
/// Returns the 11-byte space-padded short name.
pub fn generate_short_name(name: &[u8], n: u32) -> Result<[u8; SHORT_NAME_LEN]> {
    if n == 0 || n > 999999 {
        return Err(Error::InvalidArgument);
    }

    let mut short = [b' '; SHORT_NAME_LEN];

    // Find extension (last dot).
    let ext_pos = name.iter().rposition(|&b| b == b'.');
    let (base_part, ext_part) = match ext_pos {
        Some(p) if p > 0 => (&name[..p], &name[p + 1..]),
        _ => (name, &b""[..]),
    };

    // Format numeric tail `~N`.
    let mut tail_buf = [0u8; 8];
    tail_buf[0] = b'~';
    let mut tail_len = 1;
    let mut nv = n;
    let tail_start = tail_len;
    while nv > 0 {
        if tail_len < 8 {
            tail_buf[tail_len] = b'0' + (nv % 10) as u8;
            tail_len += 1;
            nv /= 10;
        } else {
            break;
        }
    }
    // Reverse the digits.
    tail_buf[tail_start..tail_len].reverse();

    // Fill base (up to 8 - tail_len chars, uppercase, skip invalid chars).
    let base_max = 8usize.saturating_sub(tail_len);
    let mut bpos = 0;
    for &b in base_part.iter() {
        if bpos >= base_max {
            break;
        }
        let ub = match b {
            b'a'..=b'z' => b - 32,
            b' ' | b'.' | b'"' | b'*' | b'+' | b',' | b'/' | b':' | b';' | b'<' | b'=' | b'>'
            | b'?' | b'[' | b'\\' | b']' | b'|' => continue,
            _ => b,
        };
        short[bpos] = ub;
        bpos += 1;
    }
    // Append tail.
    for i in 0..tail_len {
        if bpos < 8 {
            short[bpos] = tail_buf[i];
            bpos += 1;
        }
    }

    // Fill extension (up to 3 chars, uppercase).
    let mut epos = 8;
    for &b in ext_part.iter().take(3) {
        let ub = if b.is_ascii_lowercase() { b - 32 } else { b };
        short[epos] = ub;
        epos += 1;
    }

    Ok(short)
}

/// Validate that an LFN entry's checksum matches a given 8.3 name.
pub fn validate_lfn_checksum(entry: &LfnEntry, short_name: &[u8; SHORT_NAME_LEN]) -> bool {
    entry.checksum == short_name_checksum(short_name)
}

/// Return the sequence number (without last-entry flag) from an LFN entry.
pub fn lfn_sequence(entry: &LfnEntry) -> u8 {
    entry.sequence & !LFN_LAST_LONG_ENTRY
}

/// Return true if this is the last (highest-numbered) LFN entry.
pub fn lfn_is_last(entry: &LfnEntry) -> bool {
    entry.sequence & LFN_LAST_LONG_ENTRY != 0
}
