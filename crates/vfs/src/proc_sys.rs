// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! /proc/sys sysctl interface.
//!
//! Implements the `/proc/sys` virtual filesystem tree, which exposes kernel
//! tunable parameters as files. Each sysctl entry has a path, a read/write
//! handler, and a permission mode.
//!
//! # Design
//!
//! - [`SysctlEntry`] — a single sysctl parameter with handler and mode
//! - [`SysctlTable`] — global array of all registered sysctl entries
//! - `proc_sys_read` — dispatches a read to the matching sysctl handler
//! - `proc_sys_write` — dispatches a write to the matching sysctl handler
//!
//! # Reference
//!
//! Linux `fs/proc/proc_sysctl.c`, `kernel/sysctl.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of registered sysctl entries.
const MAX_SYSCTL_ENTRIES: usize = 128;

/// Maximum sysctl path length (e.g., "kernel/hostname").
const MAX_SYSCTL_PATH: usize = 128;

/// Maximum sysctl value buffer size.
const MAX_SYSCTL_VALUE: usize = 256;

/// Read-only permission bit.
const SYSCTL_PERM_READ: u16 = 0o444;

/// Write-only permission bit.
const SYSCTL_PERM_WRITE: u16 = 0o222;

/// Read-write permission bit.
const SYSCTL_PERM_RW: u16 = 0o644;

// ---------------------------------------------------------------------------
// Sysctl value type
// ---------------------------------------------------------------------------

/// Value stored for a sysctl parameter.
#[derive(Debug, Clone, Copy)]
pub enum SysctlValue {
    /// 32-bit integer.
    Int(i32),
    /// Unsigned 32-bit integer.
    Uint(u32),
    /// 64-bit integer.
    Long(i64),
    /// Unsigned 64-bit integer.
    Ulong(u64),
    /// Fixed-length string.
    String {
        data: [u8; MAX_SYSCTL_VALUE],
        len: usize,
    },
}

impl SysctlValue {
    /// Creates a new string sysctl value.
    pub fn string(s: &[u8]) -> Result<Self> {
        if s.len() > MAX_SYSCTL_VALUE {
            return Err(Error::InvalidArgument);
        }
        let mut data = [0u8; MAX_SYSCTL_VALUE];
        data[..s.len()].copy_from_slice(s);
        Ok(Self::String { data, len: s.len() })
    }

    /// Serializes the value to a text buffer. Returns bytes written.
    pub fn serialize(&self, out: &mut [u8]) -> usize {
        match self {
            Self::Int(v) => write_decimal_i32(*v, out),
            Self::Uint(v) => write_decimal_u64(*v as u64, out),
            Self::Long(v) => write_decimal_i64(*v, out),
            Self::Ulong(v) => write_decimal_u64(*v, out),
            Self::String { data, len } => {
                let copy_len = (*len).min(out.len());
                out[..copy_len].copy_from_slice(&data[..copy_len]);
                copy_len
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Sysctl entry
// ---------------------------------------------------------------------------

/// A single sysctl entry in the /proc/sys tree.
pub struct SysctlEntry {
    /// Path relative to /proc/sys (e.g., "kernel/hostname").
    pub path: [u8; MAX_SYSCTL_PATH],
    /// Valid bytes in `path`.
    pub path_len: usize,
    /// Current value.
    pub value: SysctlValue,
    /// Permission mode (POSIX bits).
    pub mode: u16,
    /// Whether this entry is currently enabled.
    pub enabled: bool,
}

impl SysctlEntry {
    /// Creates a new integer sysctl entry.
    pub fn int(path: &[u8], value: i32, mode: u16) -> Result<Self> {
        if path.is_empty() || path.len() > MAX_SYSCTL_PATH {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; MAX_SYSCTL_PATH];
        buf[..path.len()].copy_from_slice(path);
        Ok(Self {
            path: buf,
            path_len: path.len(),
            value: SysctlValue::Int(value),
            mode,
            enabled: true,
        })
    }

    /// Creates a new string sysctl entry.
    pub fn string(path: &[u8], value: &[u8], mode: u16) -> Result<Self> {
        if path.is_empty() || path.len() > MAX_SYSCTL_PATH {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; MAX_SYSCTL_PATH];
        buf[..path.len()].copy_from_slice(path);
        Ok(Self {
            path: buf,
            path_len: path.len(),
            value: SysctlValue::string(value)?,
            mode,
            enabled: true,
        })
    }

    /// Returns the path as a byte slice.
    pub fn path_bytes(&self) -> &[u8] {
        &self.path[..self.path_len]
    }

    /// Returns whether this entry is readable.
    pub fn is_readable(&self) -> bool {
        self.mode & 0o444 != 0
    }

    /// Returns whether this entry is writable.
    pub fn is_writable(&self) -> bool {
        self.mode & 0o222 != 0
    }

    /// Reads the current value into the output buffer. Returns bytes written.
    pub fn read(&self, out: &mut [u8]) -> Result<usize> {
        if !self.is_readable() {
            return Err(Error::PermissionDenied);
        }
        if !self.enabled {
            return Err(Error::NotFound);
        }
        let n = self.value.serialize(out);
        // Append newline if space available.
        if n < out.len() {
            out[n] = b'\n';
            Ok(n + 1)
        } else {
            Ok(n)
        }
    }

    /// Writes a new value by parsing the input buffer.
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        if !self.is_writable() {
            return Err(Error::PermissionDenied);
        }
        if !self.enabled {
            return Err(Error::NotFound);
        }
        // Strip trailing newline.
        let trimmed = if data.last() == Some(&b'\n') {
            &data[..data.len() - 1]
        } else {
            data
        };
        self.value = match &self.value {
            SysctlValue::Int(_) => SysctlValue::Int(parse_decimal_i32(trimmed)?),
            SysctlValue::Uint(_) => SysctlValue::Uint(parse_decimal_u64(trimmed)? as u32),
            SysctlValue::Long(_) => SysctlValue::Long(parse_decimal_i64(trimmed)?),
            SysctlValue::Ulong(_) => SysctlValue::Ulong(parse_decimal_u64(trimmed)?),
            SysctlValue::String { .. } => SysctlValue::string(trimmed)?,
        };
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Sysctl table
// ---------------------------------------------------------------------------

/// Global sysctl entry table.
pub struct SysctlTable {
    /// Entries in the table.
    entries: [Option<SysctlEntry>; MAX_SYSCTL_ENTRIES],
    /// Number of active entries.
    count: usize,
}

impl SysctlTable {
    /// Creates an empty sysctl table.
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            count: 0,
        }
    }

    /// Returns the number of entries.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Registers a new sysctl entry.
    pub fn register(&mut self, entry: SysctlEntry) -> Result<()> {
        if self.count >= MAX_SYSCTL_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate path.
        for slot in self.entries[..self.count].iter().flatten() {
            if slot.path_bytes() == entry.path_bytes() {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in &mut self.entries {
            if slot.is_none() {
                *slot = Some(entry);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters a sysctl entry by path.
    pub fn unregister(&mut self, path: &[u8]) -> Result<()> {
        for slot in &mut self.entries {
            if slot.as_ref().map(|e| e.path_bytes()) == Some(path) {
                *slot = None;
                self.count = self.count.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Finds an entry by path.
    pub fn find(&self, path: &[u8]) -> Option<&SysctlEntry> {
        self.entries
            .iter()
            .flatten()
            .find(|e| e.path_bytes() == path)
    }

    /// Finds a mutable entry by path.
    pub fn find_mut(&mut self, path: &[u8]) -> Option<&mut SysctlEntry> {
        self.entries
            .iter_mut()
            .flatten()
            .find(|e| e.path_bytes() == path)
    }
}

impl Default for SysctlTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Read/write dispatch
// ---------------------------------------------------------------------------

/// Reads a sysctl value by path. Returns bytes written to `out`.
pub fn proc_sys_read(table: &SysctlTable, path: &[u8], out: &mut [u8]) -> Result<usize> {
    let entry = table.find(path).ok_or(Error::NotFound)?;
    entry.read(out)
}

/// Writes a new value to a sysctl entry by path.
pub fn proc_sys_write(table: &mut SysctlTable, path: &[u8], data: &[u8]) -> Result<()> {
    let entry = table.find_mut(path).ok_or(Error::NotFound)?;
    entry.write(data)
}

// ---------------------------------------------------------------------------
// Integer sysctl helpers
// ---------------------------------------------------------------------------

/// Reads an integer sysctl value. Returns the value or error.
pub fn sysctl_get_int(table: &SysctlTable, path: &[u8]) -> Result<i32> {
    match table.find(path).ok_or(Error::NotFound)?.value {
        SysctlValue::Int(v) => Ok(v),
        _ => Err(Error::InvalidArgument),
    }
}

/// Sets an integer sysctl value.
pub fn sysctl_set_int(table: &mut SysctlTable, path: &[u8], value: i32) -> Result<()> {
    let entry = table.find_mut(path).ok_or(Error::NotFound)?;
    if !entry.is_writable() {
        return Err(Error::PermissionDenied);
    }
    entry.value = SysctlValue::Int(value);
    Ok(())
}

/// Gets a string sysctl value. Copies into `out`, returns bytes written.
pub fn sysctl_get_string(table: &SysctlTable, path: &[u8], out: &mut [u8]) -> Result<usize> {
    match &table.find(path).ok_or(Error::NotFound)?.value {
        SysctlValue::String { data, len } => {
            let copy_len = (*len).min(out.len());
            out[..copy_len].copy_from_slice(&data[..copy_len]);
            Ok(copy_len)
        }
        _ => Err(Error::InvalidArgument),
    }
}

/// Sets a string sysctl value.
pub fn sysctl_set_string(table: &mut SysctlTable, path: &[u8], value: &[u8]) -> Result<()> {
    let entry = table.find_mut(path).ok_or(Error::NotFound)?;
    if !entry.is_writable() {
        return Err(Error::PermissionDenied);
    }
    entry.value = SysctlValue::string(value)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers: decimal parsing/formatting
// ---------------------------------------------------------------------------

fn write_decimal_u64(mut v: u64, out: &mut [u8]) -> usize {
    if out.is_empty() {
        return 0;
    }
    if v == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut buf = [0u8; 20];
    let mut i = 20usize;
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    let digits = &buf[i..];
    let copy_len = digits.len().min(out.len());
    out[..copy_len].copy_from_slice(&digits[..copy_len]);
    copy_len
}

fn write_decimal_i32(v: i32, out: &mut [u8]) -> usize {
    if v < 0 {
        if out.is_empty() {
            return 0;
        }
        out[0] = b'-';
        write_decimal_u64((-v) as u64, &mut out[1..]) + 1
    } else {
        write_decimal_u64(v as u64, out)
    }
}

fn write_decimal_i64(v: i64, out: &mut [u8]) -> usize {
    if v < 0 {
        if out.is_empty() {
            return 0;
        }
        out[0] = b'-';
        write_decimal_u64((-v) as u64, &mut out[1..]) + 1
    } else {
        write_decimal_u64(v as u64, out)
    }
}

fn parse_decimal_u64(s: &[u8]) -> Result<u64> {
    if s.is_empty() {
        return Err(Error::InvalidArgument);
    }
    let mut result = 0u64;
    for &b in s {
        if b < b'0' || b > b'9' {
            return Err(Error::InvalidArgument);
        }
        result = result.checked_mul(10).ok_or(Error::InvalidArgument)?;
        result = result
            .checked_add((b - b'0') as u64)
            .ok_or(Error::InvalidArgument)?;
    }
    Ok(result)
}

fn parse_decimal_i32(s: &[u8]) -> Result<i32> {
    if s.is_empty() {
        return Err(Error::InvalidArgument);
    }
    let (neg, digits) = if s[0] == b'-' {
        (true, &s[1..])
    } else {
        (false, s)
    };
    let v = parse_decimal_u64(digits)? as i32;
    Ok(if neg { -v } else { v })
}

fn parse_decimal_i64(s: &[u8]) -> Result<i64> {
    if s.is_empty() {
        return Err(Error::InvalidArgument);
    }
    let (neg, digits) = if s[0] == b'-' {
        (true, &s[1..])
    } else {
        (false, s)
    };
    let v = parse_decimal_u64(digits)? as i64;
    Ok(if neg { -v } else { v })
}
