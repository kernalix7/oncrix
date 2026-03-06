// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Mount option parser for filesystem mount data strings.
//!
//! Provides a generic, allocation-free parser for comma-separated
//! key=value mount option strings, as passed to `mount(2)` in the
//! `data` argument. Used by all filesystem implementations.

use oncrix_lib::{Error, Result};

/// Maximum length of a single option key.
pub const KEY_MAX: usize = 64;
/// Maximum length of a single option value.
pub const VAL_MAX: usize = 256;
/// Maximum number of options in one parse pass.
pub const OPTS_MAX: usize = 32;

/// A single parsed mount option.
#[derive(Debug, Clone, Copy)]
pub struct ParsedOption<'a> {
    /// Option key (e.g., `"size"`, `"mode"`).
    pub key: &'a [u8],
    /// Option value; `None` for bare keys (e.g., `"ro"`, `"noexec"`).
    pub value: Option<&'a [u8]>,
}

impl<'a> ParsedOption<'a> {
    /// Create a key-only option.
    pub const fn bare(key: &'a [u8]) -> Self {
        ParsedOption { key, value: None }
    }

    /// Create a key=value option.
    pub const fn kv(key: &'a [u8], value: &'a [u8]) -> Self {
        ParsedOption {
            key,
            value: Some(value),
        }
    }

    /// Return the value as a UTF-8 string slice, if valid.
    pub fn value_str(&self) -> Option<&'a str> {
        self.value.and_then(|v| core::str::from_utf8(v).ok())
    }

    /// Parse the value as a decimal u64.
    pub fn value_u64(&self) -> Result<u64> {
        let s = self.value_str().ok_or(Error::InvalidArgument)?;
        parse_u64(s.as_bytes())
    }

    /// Parse the value as an octal u32 (for mode= options).
    pub fn value_octal(&self) -> Result<u32> {
        let v = self.value.ok_or(Error::InvalidArgument)?;
        parse_octal(v)
    }
}

/// Iterator over parsed mount options from a raw data string.
pub struct OptionIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> OptionIter<'a> {
    /// Create a new iterator over the option string.
    pub fn new(data: &'a [u8]) -> Self {
        OptionIter { data, pos: 0 }
    }
}

impl<'a> Iterator for OptionIter<'a> {
    type Item = ParsedOption<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // Skip leading commas.
        while self.pos < self.data.len() && self.data[self.pos] == b',' {
            self.pos += 1;
        }
        if self.pos >= self.data.len() {
            return None;
        }
        let start = self.pos;
        // Find end of this token.
        while self.pos < self.data.len() && self.data[self.pos] != b',' {
            self.pos += 1;
        }
        let token = &self.data[start..self.pos];
        // Split on first '='.
        if let Some(eq) = token.iter().position(|&b| b == b'=') {
            Some(ParsedOption::kv(&token[..eq], &token[eq + 1..]))
        } else {
            Some(ParsedOption::bare(token))
        }
    }
}

/// Parsed mount options collection.
pub struct MountOptions<'a> {
    opts: [Option<ParsedOption<'a>>; OPTS_MAX],
    count: usize,
}

impl<'a> MountOptions<'a> {
    /// Parse a mount data string into a collection of options.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let mut opts = [None; OPTS_MAX];
        let mut count = 0;
        for opt in OptionIter::new(data) {
            if count >= OPTS_MAX {
                return Err(Error::InvalidArgument);
            }
            opts[count] = Some(opt);
            count += 1;
        }
        Ok(MountOptions { opts, count })
    }

    /// Look up an option by key name.
    pub fn get(&self, key: &[u8]) -> Option<&ParsedOption<'a>> {
        for opt in self.opts[..self.count].iter().flatten() {
            if opt.key == key {
                return Some(opt);
            }
        }
        None
    }

    /// Check if a bare flag is present.
    pub fn has_flag(&self, key: &[u8]) -> bool {
        self.get(key).is_some()
    }

    /// Get a u64 value for a key.
    pub fn get_u64(&self, key: &[u8]) -> Result<Option<u64>> {
        match self.get(key) {
            Some(opt) => Ok(Some(opt.value_u64()?)),
            None => Ok(None),
        }
    }

    /// Get an octal u32 value for a key (used for `mode=`).
    pub fn get_mode(&self, key: &[u8]) -> Result<Option<u32>> {
        match self.get(key) {
            Some(opt) => Ok(Some(opt.value_octal()?)),
            None => Ok(None),
        }
    }

    /// Return the count of parsed options.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Iterate over all parsed options.
    pub fn iter(&self) -> impl Iterator<Item = &ParsedOption<'a>> {
        self.opts[..self.count].iter().flatten()
    }
}

/// Parse a decimal integer from a byte slice.
pub fn parse_u64(s: &[u8]) -> Result<u64> {
    if s.is_empty() {
        return Err(Error::InvalidArgument);
    }
    let mut result: u64 = 0;
    for &b in s {
        if !b.is_ascii_digit() {
            return Err(Error::InvalidArgument);
        }
        result = result.checked_mul(10).ok_or(Error::InvalidArgument)?;
        result = result
            .checked_add((b - b'0') as u64)
            .ok_or(Error::InvalidArgument)?;
    }
    Ok(result)
}

/// Parse an octal integer from a byte slice.
pub fn parse_octal(s: &[u8]) -> Result<u32> {
    if s.is_empty() {
        return Err(Error::InvalidArgument);
    }
    // Skip optional leading '0'.
    let s = if s[0] == b'0' && s.len() > 1 {
        &s[1..]
    } else {
        s
    };
    let mut result: u32 = 0;
    for &b in s {
        if !(b'0'..=b'7').contains(&b) {
            return Err(Error::InvalidArgument);
        }
        result = result.checked_mul(8).ok_or(Error::InvalidArgument)?;
        result = result
            .checked_add((b - b'0') as u32)
            .ok_or(Error::InvalidArgument)?;
    }
    Ok(result)
}

/// Standard mount option keys.
pub mod keys {
    /// Read-only mount.
    pub const RO: &[u8] = b"ro";
    /// Read-write mount.
    pub const RW: &[u8] = b"rw";
    /// No access time updates.
    pub const NOATIME: &[u8] = b"noatime";
    /// No execution of binaries.
    pub const NOEXEC: &[u8] = b"noexec";
    /// No set-UID/GID effects.
    pub const NOSUID: &[u8] = b"nosuid";
    /// Size limit (e.g., for tmpfs).
    pub const SIZE: &[u8] = b"size";
    /// Default file mode.
    pub const MODE: &[u8] = b"mode";
    /// Default directory mode.
    pub const DMODE: &[u8] = b"dmode";
    /// Mount UID.
    pub const UID: &[u8] = b"uid";
    /// Mount GID.
    pub const GID: &[u8] = b"gid";
}

/// Validate that all options in a collection are from a set of known keys.
pub fn validate_known_options(opts: &MountOptions<'_>, known: &[&[u8]]) -> Result<()> {
    for opt in opts.iter() {
        let found = known.iter().any(|k| *k == opt.key);
        if !found {
            return Err(Error::InvalidArgument);
        }
    }
    Ok(())
}
