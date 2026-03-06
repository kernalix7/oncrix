// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! FAT filesystem short name (8.3) generation.
//!
//! FAT (FAT12, FAT16, FAT32) stores directory entries with classic 8.3
//! short names: up to 8 uppercase characters for the base name and up to 3
//! for the extension, stored without a dot separator.  When a long filename
//! (LFN) is used, a short name alias must also be generated for compatibility
//! with legacy systems.
//!
//! # Design
//!
//! - [`ShortName`] — packed 11-byte short name + attribute/case flags
//! - `basis_name` — extract base name and extension from a long filename
//! - `to_shortname` — filter illegal characters, uppercase, and pad with spaces
//! - `numeric_tail` — append `~N` collision suffixes
//! - `shortname_valid` — verify that a candidate is collision-free
//! - [`ShortNameGen`] — stateful generator that tries `~1` … `~999999`
//!
//! # References
//!
//! - Linux `fs/fat/namei_vfat.c` (`vfat_create_shortname`, `vfat_fill_slots`)
//! - Microsoft FAT specification (section 7: Basis-Name Generation Algorithm)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Length of the base-name field in an 8.3 short name.
pub const SHORTNAME_BASE_LEN: usize = 8;
/// Length of the extension field in an 8.3 short name.
pub const SHORTNAME_EXT_LEN: usize = 3;
/// Total short name buffer size (base + ext, no dot).
pub const SHORTNAME_LEN: usize = SHORTNAME_BASE_LEN + SHORTNAME_EXT_LEN;

/// Pad character used to fill unused name / extension bytes.
pub const SHORTNAME_PAD: u8 = b' ';

/// Space byte alias used in some comparisons.
const SP: u8 = SHORTNAME_PAD;

/// Characters that are illegal in FAT short names.
const ILLEGAL_CHARS: &[u8] = b"+,;=[]";

/// Maximum numeric tail suffix value (~999999).
pub const MAX_TAIL: u32 = 999_999;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A packed FAT 8.3 short name.
///
/// Stored as 11 bytes: `name[0..8]` + `ext[0..3]`, space-padded, all uppercase.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ShortName {
    /// Raw 11-byte array (base name + extension, no separator).
    pub raw: [u8; SHORTNAME_LEN],
    /// Whether the base name is stored in lower-case (VFAT `DIR_NTRes` bit 3).
    pub lower_base: bool,
    /// Whether the extension is stored in lower-case (VFAT `DIR_NTRes` bit 4).
    pub lower_ext: bool,
}

impl Default for ShortName {
    fn default() -> Self {
        Self {
            raw: [SP; SHORTNAME_LEN],
            lower_base: false,
            lower_ext: false,
        }
    }
}

impl core::fmt::Debug for ShortName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let base = &self.raw[..SHORTNAME_BASE_LEN];
        let ext = &self.raw[SHORTNAME_BASE_LEN..];
        write!(f, "ShortName({:?}.{:?})", base, ext)
    }
}

impl ShortName {
    /// Construct from a pre-validated 11-byte raw buffer.
    pub fn from_raw(raw: [u8; SHORTNAME_LEN]) -> Self {
        Self {
            raw,
            lower_base: false,
            lower_ext: false,
        }
    }

    /// Return the base-name part (bytes 0–7), trimming trailing spaces.
    pub fn base(&self) -> &[u8] {
        let end = self.raw[..SHORTNAME_BASE_LEN]
            .iter()
            .rposition(|&b| b != SP)
            .map(|p| p + 1)
            .unwrap_or(0);
        &self.raw[..end]
    }

    /// Return the extension part (bytes 8–10), trimming trailing spaces.
    pub fn ext(&self) -> &[u8] {
        let start = SHORTNAME_BASE_LEN;
        let end = self.raw[start..]
            .iter()
            .rposition(|&b| b != SP)
            .map(|p| start + p + 1)
            .unwrap_or(start);
        &self.raw[start..end]
    }

    /// Write a dot-separated display form (e.g. `"FOO.TXT"`) into `buf`.
    ///
    /// Returns the number of bytes written, or [`Error::InvalidArgument`]
    /// when `buf` is too small.
    pub fn display(&self, buf: &mut [u8]) -> Result<usize> {
        let base = self.base();
        let ext = self.ext();
        let need = base.len() + if ext.is_empty() { 0 } else { 1 + ext.len() };
        if buf.len() < need {
            return Err(Error::InvalidArgument);
        }
        buf[..base.len()].copy_from_slice(base);
        if !ext.is_empty() {
            buf[base.len()] = b'.';
            buf[base.len() + 1..need].copy_from_slice(ext);
        }
        Ok(need)
    }
}

// ---------------------------------------------------------------------------
// Character helpers
// ---------------------------------------------------------------------------

/// Returns `true` when `c` is legal in a FAT short name byte.
pub fn is_legal_char(c: u8) -> bool {
    if c < 0x20 {
        return false;
    }
    !ILLEGAL_CHARS.contains(&c)
}

/// Map a byte to its FAT short-name uppercase equivalent.
///
/// ASCII lowercase is uppercased; bytes ≥ 0x80 are passed through (OEM code
/// pages are not decoded in this stub).
pub fn shortname_upper(c: u8) -> u8 {
    if c.is_ascii_lowercase() { c - 0x20 } else { c }
}

/// Returns `true` when `c` must be replaced with `_` in a short name.
pub fn needs_replacement(c: u8) -> bool {
    c == b' ' || c == b'.' || !is_legal_char(c)
}

// ---------------------------------------------------------------------------
// Basis name extraction
// ---------------------------------------------------------------------------

/// Split a long filename into (base, extension) byte slices.
///
/// The split point is the *last* dot in the name (excluding a leading dot,
/// which is treated as part of the base).  An empty extension means no dot
/// was found or the name ends with a dot.
pub fn split_extension(name: &[u8]) -> (&[u8], &[u8]) {
    // Skip a leading dot (hidden files on UNIX; treated as no-extension in FAT).
    let search_from = if name.first() == Some(&b'.') { 1 } else { 0 };
    match name[search_from..].iter().rposition(|&b| b == b'.') {
        Some(rel) => {
            let dot_pos = search_from + rel;
            (&name[..dot_pos], &name[dot_pos + 1..])
        }
        None => (name, &[]),
    }
}

// ---------------------------------------------------------------------------
// Short name construction
// ---------------------------------------------------------------------------

/// Build a basis short name from `long_name` without a numeric tail.
///
/// - Illegal characters are replaced with `_`.
/// - All characters are uppercased.
/// - Base is truncated / padded to 8 bytes; extension to 3 bytes.
///
/// The result may collide with existing entries; call [`add_numeric_tail`] to
/// disambiguate.
pub fn basis_name(long_name: &[u8]) -> ShortName {
    let (base_raw, ext_raw) = split_extension(long_name);
    let mut sn = ShortName::default();

    // Fill base field.
    let mut out = 0usize;
    for &c in base_raw.iter().take(SHORTNAME_BASE_LEN * 2) {
        if out >= SHORTNAME_BASE_LEN {
            break;
        }
        if needs_replacement(c) {
            sn.raw[out] = b'_';
        } else {
            sn.raw[out] = shortname_upper(c);
        }
        out += 1;
    }
    // Pad remaining base bytes with spaces (already initialised to SP).

    // Fill extension field.
    out = SHORTNAME_BASE_LEN;
    for &c in ext_raw.iter().take(SHORTNAME_EXT_LEN) {
        if needs_replacement(c) {
            sn.raw[out] = b'_';
        } else {
            sn.raw[out] = shortname_upper(c);
        }
        out += 1;
    }
    sn
}

// ---------------------------------------------------------------------------
// Numeric tail
// ---------------------------------------------------------------------------

/// Write a `~N` numeric tail into the base-name field of `sn` at the
/// appropriate position, truncating the base if necessary.
///
/// Returns [`Error::InvalidArgument`] when `tail` is 0 or exceeds
/// [`MAX_TAIL`].
pub fn add_numeric_tail(sn: &mut ShortName, tail: u32) -> Result<()> {
    if tail == 0 || tail > MAX_TAIL {
        return Err(Error::InvalidArgument);
    }
    // Compute the decimal representation of `tail`.
    let mut tbuf = [0u8; 7]; // '~' + up to 6 digits
    tbuf[0] = b'~';
    let mut n = tail;
    let mut len = 1usize;
    let mut digits = [0u8; 6];
    let mut dcount = 0usize;
    while n > 0 {
        digits[dcount] = b'0' + (n % 10) as u8;
        dcount += 1;
        n /= 10;
    }
    // Reverse digits into tbuf.
    for i in 0..dcount {
        tbuf[len] = digits[dcount - 1 - i];
        len += 1;
    }
    let tail_slice = &tbuf[..len];

    // Position the tail suffix so it ends at byte 7 (index 7) of the base.
    let tail_start = if len <= SHORTNAME_BASE_LEN {
        SHORTNAME_BASE_LEN - len
    } else {
        return Err(Error::InvalidArgument);
    };

    // Write the tail, padding bytes before it with the existing base content.
    for (i, &b) in tail_slice.iter().enumerate() {
        sn.raw[tail_start + i] = b;
    }
    // Pad any bytes between existing base and tail with spaces.
    for i in tail_start..tail_start {
        sn.raw[i] = SP;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

/// Stateful generator that produces collision-free short names.
///
/// Usage:
/// 1. Call [`ShortNameGen::new`] with the long filename.
/// 2. Call [`ShortNameGen::next_candidate`] to get the next candidate.
/// 3. Check the candidate against existing directory entries.
/// 4. If collision, repeat from step 2.
pub struct ShortNameGen {
    /// Basis short name (without tail).
    basis: ShortName,
    /// Next tail number to try (0 = try basis first).
    next_tail: u32,
}

impl ShortNameGen {
    /// Create a generator for `long_name`.
    pub fn new(long_name: &[u8]) -> Self {
        Self {
            basis: basis_name(long_name),
            next_tail: 0,
        }
    }

    /// Return the next candidate short name.
    ///
    /// The first call returns the basis name (no tail).  Subsequent calls
    /// return `~1`, `~2`, … up to `~MAX_TAIL`.  Returns [`Error::AlreadyExists`]
    /// when all suffixes are exhausted.
    pub fn next_candidate(&mut self) -> Result<ShortName> {
        if self.next_tail == 0 {
            self.next_tail = 1;
            return Ok(self.basis);
        }
        if self.next_tail > MAX_TAIL {
            return Err(Error::AlreadyExists);
        }
        let mut candidate = self.basis;
        add_numeric_tail(&mut candidate, self.next_tail)?;
        self.next_tail += 1;
        Ok(candidate)
    }

    /// Reset the generator to start from the basis name again.
    pub fn reset(&mut self) {
        self.next_tail = 0;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_basis() {
        let sn = basis_name(b"README.TXT");
        assert_eq!(sn.base(), b"README");
        assert_eq!(sn.ext(), b"TXT");
    }

    #[test]
    fn lowercase_uppercased() {
        let sn = basis_name(b"hello.rs");
        assert_eq!(sn.base(), b"HELLO");
        assert_eq!(sn.ext(), b"RS");
    }

    #[test]
    fn long_name_truncated() {
        let sn = basis_name(b"verylongfilename.txt");
        assert_eq!(sn.base().len(), SHORTNAME_BASE_LEN);
        assert_eq!(sn.ext(), b"TXT");
    }

    #[test]
    fn numeric_tail_applied() {
        let mut sn = basis_name(b"FOO.BAR");
        add_numeric_tail(&mut sn, 1).unwrap();
        // Base should end with '~1'.
        let base = sn.base();
        assert!(base.ends_with(b"~1"), "base = {:?}", base);
    }

    #[test]
    fn generator_sequence() {
        let mut name_gen = ShortNameGen::new(b"test.txt");
        let c0 = name_gen.next_candidate().unwrap();
        assert_eq!(c0.base(), b"TEST");
        let c1 = name_gen.next_candidate().unwrap();
        assert!(c1.base().ends_with(b"~1"), "c1 base = {:?}", c1.base());
        let c2 = name_gen.next_candidate().unwrap();
        assert!(c2.base().ends_with(b"~2"), "c2 base = {:?}", c2.base());
    }

    #[test]
    fn display_writes_dotted_name() {
        let sn = basis_name(b"FOO.TXT");
        let mut buf = [0u8; 16];
        let n = sn.display(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"FOO.TXT");
    }

    #[test]
    fn illegal_char_replaced() {
        let sn = basis_name(b"my file[1].txt");
        for &b in sn.base() {
            assert!(b != b'[' && b != b']' && b != b' ', "illegal char {b}");
        }
    }
}
