// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel boot parameter parsing.
//!
//! Parses the kernel command line (passed by the bootloader) into a typed
//! parameter store. Supports the common `key=value` and bare flag formats
//! used by Linux-compatible bootloaders (GRUB, systemd-boot, etc.).
//!
//! # Architecture
//!
//! | Component         | Purpose                                            |
//! |-------------------|----------------------------------------------------|
//! | [`ParamValue`]    | Typed parameter value (bool, integer, string)      |
//! | [`Param`]         | A single parsed key=value parameter                |
//! | [`ParamStore`]    | Holds all parsed parameters, supports typed lookup |
//! | [`parse_cmdline`] | Parse a raw command-line byte string               |
//!
//! # Command-line Format
//!
//! ```text
//! key1=value1 key2=value2 bare_flag key3="value with spaces"
//! ```
//!
//! - `key=value` — sets key to the string value.
//! - `key` (no `=`) — sets key to the boolean value `true`.
//! - `key=0` / `key=1` — booleans.
//! - `key=N` where N is a decimal integer — integer parameter.
//! - Quoted values strip surrounding double quotes.
//! - Maximum command line length: `MAX_CMDLINE_LEN` bytes.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum length of the full kernel command line.
pub const MAX_CMDLINE_LEN: usize = 4096;

/// Maximum length of a single parameter key.
pub const MAX_KEY_LEN: usize = 64;

/// Maximum length of a parameter value string.
pub const MAX_VAL_LEN: usize = 256;

/// Maximum number of parameters.
pub const MAX_PARAMS: usize = 128;

// ---------------------------------------------------------------------------
// Parameter value
// ---------------------------------------------------------------------------

/// Typed parameter value.
#[derive(Debug, Clone, Copy)]
pub enum ParamValue {
    /// Boolean flag (present with no `=` or `=0`/`=1`).
    Bool(bool),
    /// Signed 64-bit integer.
    Int(i64),
    /// String value (NUL-terminated, max `MAX_VAL_LEN` bytes).
    Str([u8; MAX_VAL_LEN], u16),
}

impl ParamValue {
    /// Create a string parameter value from a byte slice.
    pub fn from_str(s: &[u8]) -> Self {
        let len = s.len().min(MAX_VAL_LEN);
        let mut buf = [0u8; MAX_VAL_LEN];
        buf[..len].copy_from_slice(&s[..len]);
        Self::Str(buf, len as u16)
    }

    /// Try to interpret as bool.
    pub fn as_bool(&self) -> Option<bool> {
        match *self {
            Self::Bool(b) => Some(b),
            Self::Int(0) => Some(false),
            Self::Int(1) => Some(true),
            Self::Int(_) => None,
            Self::Str(buf, len) => {
                let s = &buf[..len as usize];
                if s == b"1" || s == b"true" || s == b"yes" || s == b"on" {
                    Some(true)
                } else if s == b"0" || s == b"false" || s == b"no" || s == b"off" {
                    Some(false)
                } else {
                    None
                }
            }
        }
    }

    /// Try to interpret as a signed 64-bit integer.
    pub fn as_int(&self) -> Option<i64> {
        match *self {
            Self::Int(n) => Some(n),
            Self::Bool(b) => Some(b as i64),
            Self::Str(buf, len) => parse_i64(&buf[..len as usize]),
        }
    }

    /// Try to interpret as a string slice.
    pub fn as_str(&self) -> &[u8] {
        match self {
            Self::Str(buf, len) => &buf[..*len as usize],
            _ => b"",
        }
    }
}

impl Default for ParamValue {
    fn default() -> Self {
        Self::Bool(false)
    }
}

// ---------------------------------------------------------------------------
// Parameter entry
// ---------------------------------------------------------------------------

/// A single key-value parameter.
#[derive(Clone, Copy)]
pub struct Param {
    /// Parameter key (NUL-terminated).
    pub key: [u8; MAX_KEY_LEN],
    /// Key length (excluding NUL).
    pub key_len: u8,
    /// Parameter value.
    pub value: ParamValue,
    /// Whether this slot is occupied.
    pub occupied: bool,
}

impl Param {
    /// Create a parameter entry.
    pub fn new(key: &[u8], value: ParamValue) -> Self {
        let len = key.len().min(MAX_KEY_LEN - 1);
        let mut buf = [0u8; MAX_KEY_LEN];
        buf[..len].copy_from_slice(&key[..len]);
        Self {
            key: buf,
            key_len: len as u8,
            value,
            occupied: true,
        }
    }

    /// Return the key as a byte slice.
    pub fn key_bytes(&self) -> &[u8] {
        &self.key[..self.key_len as usize]
    }
}

impl Default for Param {
    fn default() -> Self {
        Self {
            key: [0u8; MAX_KEY_LEN],
            key_len: 0,
            value: ParamValue::Bool(false),
            occupied: false,
        }
    }
}

impl core::fmt::Debug for Param {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Param")
            .field(
                "key",
                &core::str::from_utf8(self.key_bytes()).unwrap_or("?"),
            )
            .field("value", &self.value)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Parameter store
// ---------------------------------------------------------------------------

/// Holds all parsed kernel boot parameters.
pub struct ParamStore {
    params: [Param; MAX_PARAMS],
    count: usize,
}

impl ParamStore {
    /// Create an empty parameter store.
    pub const fn new() -> Self {
        Self {
            params: [Param {
                key: [0u8; MAX_KEY_LEN],
                key_len: 0,
                value: ParamValue::Bool(false),
                occupied: false,
            }; MAX_PARAMS],
            count: 0,
        }
    }

    /// Insert a parameter. Overwrites existing key if present.
    pub fn insert(&mut self, key: &[u8], value: ParamValue) -> Result<()> {
        // Overwrite existing.
        for i in 0..self.count {
            if self.params[i].occupied && self.params[i].key_bytes() == key {
                self.params[i].value = value;
                return Ok(());
            }
        }
        if self.count >= MAX_PARAMS {
            return Err(Error::OutOfMemory);
        }
        self.params[self.count] = Param::new(key, value);
        self.count += 1;
        Ok(())
    }

    /// Look up a parameter by key.
    pub fn get(&self, key: &[u8]) -> Option<&ParamValue> {
        self.params[..self.count]
            .iter()
            .find(|p| p.occupied && p.key_bytes() == key)
            .map(|p| &p.value)
    }

    /// Look up a boolean parameter.
    pub fn get_bool(&self, key: &[u8]) -> Option<bool> {
        self.get(key)?.as_bool()
    }

    /// Look up an integer parameter.
    pub fn get_int(&self, key: &[u8]) -> Option<i64> {
        self.get(key)?.as_int()
    }

    /// Look up a string parameter.
    pub fn get_str(&self, key: &[u8]) -> Option<&[u8]> {
        match self.get(key)? {
            ParamValue::Str(buf, len) => Some(&buf[..*len as usize]),
            _ => None,
        }
    }

    /// Returns true if the key exists (bare flag or any value).
    pub fn has(&self, key: &[u8]) -> bool {
        self.get(key).is_some()
    }

    /// Number of parameters stored.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no parameters are stored.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterate over all parameters.
    pub fn iter(&self) -> impl Iterator<Item = &Param> {
        self.params[..self.count].iter().filter(|p| p.occupied)
    }
}

impl Default for ParamStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Command-line parser
// ---------------------------------------------------------------------------

/// Parse a raw kernel command-line byte string into a [`ParamStore`].
///
/// The command line format is: space-separated tokens of the form:
/// - `key=value` — key with string/int/bool value
/// - `key` — bare flag (treated as `key=true`)
/// - Quoted strings: `key="value with spaces"` (only leading/trailing `"`)
///
/// Returns `Err(InvalidArgument)` if the command line is too long.
pub fn parse_cmdline(cmdline: &[u8]) -> Result<ParamStore> {
    if cmdline.len() > MAX_CMDLINE_LEN {
        return Err(Error::InvalidArgument);
    }
    let mut store = ParamStore::new();
    let mut pos = 0;

    while pos < cmdline.len() {
        // Skip whitespace.
        while pos < cmdline.len() && cmdline[pos] == b' ' {
            pos += 1;
        }
        if pos >= cmdline.len() {
            break;
        }

        // Read key (up to '=' or whitespace or end).
        let key_start = pos;
        while pos < cmdline.len() && cmdline[pos] != b'=' && cmdline[pos] != b' ' {
            pos += 1;
        }
        let key = &cmdline[key_start..pos];
        if key.is_empty() {
            continue;
        }

        if pos >= cmdline.len() || cmdline[pos] == b' ' {
            // Bare flag.
            store.insert(key, ParamValue::Bool(true))?;
            continue;
        }

        // Consume '='.
        pos += 1;

        // Read value.
        let value = if pos < cmdline.len() && cmdline[pos] == b'"' {
            // Quoted value: skip opening quote, read to closing quote.
            pos += 1;
            let val_start = pos;
            while pos < cmdline.len() && cmdline[pos] != b'"' {
                pos += 1;
            }
            let v = &cmdline[val_start..pos];
            if pos < cmdline.len() && cmdline[pos] == b'"' {
                pos += 1; // skip closing quote
            }
            ParamValue::from_str(v)
        } else {
            let val_start = pos;
            while pos < cmdline.len() && cmdline[pos] != b' ' {
                pos += 1;
            }
            let v = &cmdline[val_start..pos];
            classify_value(v)
        };

        store.insert(key, value)?;
    }

    Ok(store)
}

/// Classify a raw value byte slice as bool, int, or string.
fn classify_value(v: &[u8]) -> ParamValue {
    // Bool literals.
    if v == b"true" || v == b"yes" || v == b"on" || v == b"1" {
        return ParamValue::Bool(true);
    }
    if v == b"false" || v == b"no" || v == b"off" || v == b"0" {
        return ParamValue::Bool(false);
    }
    // Try integer.
    if let Some(n) = parse_i64(v) {
        return ParamValue::Int(n);
    }
    // Fall back to string.
    ParamValue::from_str(v)
}

/// Parse a byte slice as a signed decimal integer.
fn parse_i64(s: &[u8]) -> Option<i64> {
    if s.is_empty() {
        return None;
    }
    let (neg, digits) = if s[0] == b'-' {
        (true, &s[1..])
    } else {
        (false, s)
    };
    if digits.is_empty() {
        return None;
    }
    let mut n: i64 = 0;
    for &b in digits {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((b - b'0') as i64)?;
    }
    Some(if neg { -n } else { n })
}
