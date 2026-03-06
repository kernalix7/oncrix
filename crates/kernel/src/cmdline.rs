// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel command line parser.
//!
//! Parses the boot command line string passed by the bootloader
//! into structured key-value parameters. Supports the standard
//! `key=value` and bare `key` (flag) formats separated by spaces.
//!
//! # Examples (conceptual)
//!
//! ```text
//! root=/dev/sda1 console=ttyS0,115200 debug loglevel=7
//! ```
//!
//! The parser handles up to 32 parameters with keys up to 64 bytes
//! and values up to 128 bytes. All storage is stack-allocated to
//! avoid heap usage during early boot.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum number of parameters that can be parsed.
const MAX_PARAMS: usize = 32;

/// Maximum key length in bytes.
const MAX_KEY_LEN: usize = 64;

/// Maximum value length in bytes.
const MAX_VALUE_LEN: usize = 128;

/// Maximum raw command line length in bytes.
const MAX_RAW_LEN: usize = 512;

/// Maximum console device name length in bytes.
const MAX_DEVICE_LEN: usize = 32;

// ── Well-known parameter keys ──────────────────────────────────────

/// Root filesystem device (e.g., `root=/dev/sda1`).
pub const PARAM_ROOT: &[u8] = b"root";

/// Console device (e.g., `console=ttyS0,115200`).
pub const PARAM_CONSOLE: &[u8] = b"console";

/// Init program path (e.g., `init=/sbin/init`).
pub const PARAM_INIT: &[u8] = b"init";

/// Enable debug mode (flag, no value required).
pub const PARAM_DEBUG: &[u8] = b"debug";

/// Suppress boot messages (flag, no value required).
pub const PARAM_QUIET: &[u8] = b"quiet";

/// Panic timeout in seconds (e.g., `panic=10`).
pub const PARAM_PANIC: &[u8] = b"panic";

/// Memory limit (e.g., `mem=512M`).
pub const PARAM_MEM: &[u8] = b"mem";

/// Maximum CPUs to use (e.g., `maxcpus=4`).
pub const PARAM_MAXCPUS: &[u8] = b"maxcpus";

/// Kernel log level (e.g., `loglevel=7`).
pub const PARAM_LOGLEVEL: &[u8] = b"loglevel";

// ── Helper functions ───────────────────────────────────────────────

/// Parse decimal ASCII digits to `u64` with overflow checking.
///
/// Returns `None` if `bytes` is empty, contains non-digit
/// characters, or the result would overflow `u64`.
pub fn parse_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut result: u64 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        let digit = (b - b'0') as u64;
        result = result.checked_mul(10)?;
        result = result.checked_add(digit)?;
    }
    Some(result)
}

/// Parse a size string with optional suffix.
///
/// Supported suffixes (case-sensitive):
/// - `K` — kibibytes (1024)
/// - `M` — mebibytes (1024^2)
/// - `G` — gibibytes (1024^3)
/// - No suffix — plain bytes
///
/// Returns `None` if the input is empty, malformed, or overflows.
pub fn parse_size(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let last = bytes[bytes.len() - 1];
    let (digits, multiplier): (&[u8], u64) = match last {
        b'K' => (&bytes[..bytes.len() - 1], 1024),
        b'M' => (&bytes[..bytes.len() - 1], 1024 * 1024),
        b'G' => (&bytes[..bytes.len() - 1], 1024 * 1024 * 1024),
        _ => (bytes, 1),
    };
    let base = parse_u64(digits)?;
    base.checked_mul(multiplier)
}

// ── CmdlineParam ───────────────────────────────────────────────────

/// A single parsed command line parameter.
///
/// Stores a key and an optional value. Flags like `debug` have
/// `has_value` set to `false` and an empty value buffer.
#[derive(Clone, Copy)]
pub struct CmdlineParam {
    /// Key bytes (null-padded, not null-terminated).
    key: [u8; MAX_KEY_LEN],
    /// Number of valid bytes in `key`.
    key_len: usize,
    /// Value bytes (null-padded, not null-terminated).
    value: [u8; MAX_VALUE_LEN],
    /// Number of valid bytes in `value`.
    value_len: usize,
    /// Whether this parameter has an explicit value.
    has_value: bool,
}

impl CmdlineParam {
    /// Create an empty parameter.
    const fn empty() -> Self {
        Self {
            key: [0u8; MAX_KEY_LEN],
            key_len: 0,
            value: [0u8; MAX_VALUE_LEN],
            value_len: 0,
            has_value: false,
        }
    }

    /// Return the key as a byte slice.
    pub fn key(&self) -> &[u8] {
        &self.key[..self.key_len]
    }

    /// Return the value as a byte slice, or `None` if no value.
    pub fn value(&self) -> Option<&[u8]> {
        if self.has_value {
            Some(&self.value[..self.value_len])
        } else {
            None
        }
    }

    /// Whether this parameter has an explicit value.
    pub fn has_value(&self) -> bool {
        self.has_value
    }
}

// ── Cmdline ────────────────────────────────────────────────────────

/// Parsed kernel command line.
///
/// Holds up to [`MAX_PARAMS`] parameters parsed from the raw
/// command line string. All storage is inline (no heap allocation).
pub struct Cmdline {
    /// Parsed parameters.
    params: [CmdlineParam; MAX_PARAMS],
    /// Number of valid parameters.
    count: usize,
    /// Original raw command line bytes.
    raw: [u8; MAX_RAW_LEN],
    /// Number of valid bytes in `raw`.
    raw_len: usize,
}

impl Cmdline {
    /// Parse a command line byte string into parameters.
    ///
    /// The input is split on ASCII spaces. Each token is either a
    /// bare key (flag) or `key=value`. Leading/trailing whitespace
    /// and consecutive spaces are ignored.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if:
    /// - The input exceeds [`MAX_RAW_LEN`] bytes
    /// - A key exceeds [`MAX_KEY_LEN`] bytes
    /// - A value exceeds [`MAX_VALUE_LEN`] bytes
    /// - More than [`MAX_PARAMS`] parameters are present
    pub fn parse(input: &[u8]) -> Result<Self> {
        if input.len() > MAX_RAW_LEN {
            return Err(Error::InvalidArgument);
        }

        let mut cmdline = Self {
            params: [CmdlineParam::empty(); MAX_PARAMS],
            count: 0,
            raw: [0u8; MAX_RAW_LEN],
            raw_len: input.len(),
        };

        // Copy raw input.
        let mut i = 0;
        while i < input.len() {
            cmdline.raw[i] = input[i];
            i += 1;
        }

        // Tokenize by spaces.
        let mut pos = 0;
        while pos < input.len() {
            // Skip spaces.
            if input[pos] == b' ' {
                pos += 1;
                continue;
            }

            // Find end of token.
            let start = pos;
            while pos < input.len() && input[pos] != b' ' {
                pos += 1;
            }
            let token = &input[start..pos];

            if token.is_empty() {
                continue;
            }

            if cmdline.count >= MAX_PARAMS {
                return Err(Error::InvalidArgument);
            }

            // Split on first '='.
            let eq_pos = find_byte(token, b'=');
            let param = &mut cmdline.params[cmdline.count];

            match eq_pos {
                Some(eq) => {
                    let key_part = &token[..eq];
                    let val_part = &token[eq + 1..];

                    if key_part.len() > MAX_KEY_LEN {
                        return Err(Error::InvalidArgument);
                    }
                    if val_part.len() > MAX_VALUE_LEN {
                        return Err(Error::InvalidArgument);
                    }
                    if key_part.is_empty() {
                        return Err(Error::InvalidArgument);
                    }

                    copy_bytes(&mut param.key, key_part);
                    param.key_len = key_part.len();
                    copy_bytes(&mut param.value, val_part);
                    param.value_len = val_part.len();
                    param.has_value = true;
                }
                None => {
                    if token.len() > MAX_KEY_LEN {
                        return Err(Error::InvalidArgument);
                    }
                    copy_bytes(&mut param.key, token);
                    param.key_len = token.len();
                    param.has_value = false;
                }
            }

            cmdline.count += 1;
        }

        Ok(cmdline)
    }

    /// Get the value for a given key.
    ///
    /// Returns `Some(value_bytes)` if the key exists and has a
    /// value, or `None` if the key is not found or is a bare flag.
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        let mut i = 0;
        while i < self.count {
            if bytes_eq(self.params[i].key(), key) {
                return self.params[i].value();
            }
            i += 1;
        }
        None
    }

    /// Check whether a key is present (with or without a value).
    pub fn has(&self, key: &[u8]) -> bool {
        let mut i = 0;
        while i < self.count {
            if bytes_eq(self.params[i].key(), key) {
                return true;
            }
            i += 1;
        }
        false
    }

    /// Get a value parsed as a decimal `u64`.
    ///
    /// Returns `None` if the key is missing, has no value, or the
    /// value is not a valid decimal integer.
    pub fn get_u64(&self, key: &[u8]) -> Option<u64> {
        let val = self.get(key)?;
        parse_u64(val)
    }

    /// Get a value interpreted as a boolean.
    ///
    /// - `"1"`, `"true"`, `"yes"`, `"on"` → `Some(true)`
    /// - `"0"`, `"false"`, `"no"`, `"off"` → `Some(false)`
    /// - Key present without value → `Some(true)` (flag)
    /// - Key absent → `None`
    pub fn get_bool(&self, key: &[u8]) -> Option<bool> {
        let mut i = 0;
        while i < self.count {
            if bytes_eq(self.params[i].key(), key) {
                if !self.params[i].has_value {
                    return Some(true);
                }
                let val = self.params[i].value()?;
                return match val {
                    b"1" | b"true" | b"yes" | b"on" => Some(true),
                    b"0" | b"false" | b"no" | b"off" => Some(false),
                    _ => None,
                };
            }
            i += 1;
        }
        None
    }

    /// Return an iterator over all parsed parameters.
    pub fn iter(&self) -> CmdlineIter<'_> {
        CmdlineIter {
            cmdline: self,
            index: 0,
        }
    }

    /// Return the number of parsed parameters.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Return the raw command line as a byte slice.
    pub fn raw(&self) -> &[u8] {
        &self.raw[..self.raw_len]
    }
}

// ── CmdlineIter ────────────────────────────────────────────────────

/// Iterator over parsed command line parameters.
///
/// Yields `(key, Option<value>)` pairs for each parameter.
pub struct CmdlineIter<'a> {
    /// Reference to the owning `Cmdline`.
    cmdline: &'a Cmdline,
    /// Current iteration index.
    index: usize,
}

impl<'a> Iterator for CmdlineIter<'a> {
    type Item = (&'a [u8], Option<&'a [u8]>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.cmdline.count {
            return None;
        }
        let param = &self.cmdline.params[self.index];
        self.index += 1;
        Some((param.key(), param.value()))
    }
}

// ── ConsoleSpec ────────────────────────────────────────────────────

/// Parsed `console=` parameter specification.
///
/// Represents a console device and optional baud rate, parsed from
/// the format `device,baud_rate` (e.g., `ttyS0,115200`).
pub struct ConsoleSpec {
    /// Device name bytes.
    device: [u8; MAX_DEVICE_LEN],
    /// Number of valid bytes in `device`.
    device_len: usize,
    /// Baud rate (0 if not specified).
    baud_rate: u32,
}

impl ConsoleSpec {
    /// Parse a `console=` value (e.g., `ttyS0,115200`).
    ///
    /// If no comma is present, the entire value is the device name
    /// and the baud rate defaults to 0.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if:
    /// - The input is empty
    /// - The device name exceeds [`MAX_DEVICE_LEN`] bytes
    /// - The baud rate portion is not valid decimal
    /// - The baud rate overflows `u32`
    pub fn parse_console(value: &[u8]) -> Result<Self> {
        if value.is_empty() {
            return Err(Error::InvalidArgument);
        }

        let comma_pos = find_byte(value, b',');

        let (dev_part, baud) = match comma_pos {
            Some(cp) => {
                let dev = &value[..cp];
                let baud_bytes = &value[cp + 1..];
                let b = parse_u64(baud_bytes).ok_or(Error::InvalidArgument)?;
                if b > u32::MAX as u64 {
                    return Err(Error::InvalidArgument);
                }
                (dev, b as u32)
            }
            None => (value, 0u32),
        };

        if dev_part.is_empty() || dev_part.len() > MAX_DEVICE_LEN {
            return Err(Error::InvalidArgument);
        }

        let mut spec = Self {
            device: [0u8; MAX_DEVICE_LEN],
            device_len: dev_part.len(),
            baud_rate: baud,
        };
        copy_bytes(&mut spec.device, dev_part);

        Ok(spec)
    }

    /// Return the device name as a byte slice.
    pub fn device(&self) -> &[u8] {
        &self.device[..self.device_len]
    }

    /// Return the baud rate (0 if not specified).
    pub fn baud_rate(&self) -> u32 {
        self.baud_rate
    }
}

// ── Private helpers ────────────────────────────────────────────────

/// Find the first occurrence of `needle` in `haystack`.
fn find_byte(haystack: &[u8], needle: u8) -> Option<usize> {
    let mut i = 0;
    while i < haystack.len() {
        if haystack[i] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Copy `src` into the beginning of `dst`.
///
/// Caller must ensure `src.len() <= dst.len()`.
fn copy_bytes(dst: &mut [u8], src: &[u8]) {
    let mut i = 0;
    while i < src.len() {
        dst[i] = src[i];
        i += 1;
    }
}

/// Compare two byte slices for equality.
fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}
