// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel sysctl subsystem — runtime kernel parameter management.
//!
//! Provides a hierarchical namespace of tunable kernel parameters,
//! modeled after Linux's `/proc/sys` interface. Parameters are
//! organized into dotted paths (e.g., `kernel.hostname`,
//! `vm.swappiness`, `net.ipv4.ip_forward`) and can be read or
//! written at runtime.
//!
//! # Architecture
//!
//! ```text
//!  SysctlRegistry (global wrapper)
//!    └──► SysctlTable (256 entries)
//!           └──► SysctlEntry
//!                  ├── path ("kernel.hostname")
//!                  ├── value_type (Integer | String | Boolean)
//!                  ├── int_value / str_value
//!                  └── min / max (for Integer), read_only flag
//! ```
//!
//! Reference: Linux `kernel/sysctl.c`, `include/linux/sysctl.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum length of a sysctl path (bytes).
const MAX_PATH_LEN: usize = 128;

/// Maximum length of a sysctl string value (bytes).
const MAX_STR_VALUE_LEN: usize = 128;

/// Maximum number of sysctl entries in the table.
const MAX_SYSCTL_ENTRIES: usize = 256;

// -------------------------------------------------------------------
// SysctlType
// -------------------------------------------------------------------

/// The data type of a sysctl parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SysctlType {
    /// Signed 64-bit integer value with optional min/max bounds.
    #[default]
    Integer,
    /// UTF-8 string value up to 128 bytes.
    String,
    /// Boolean value (true/false).
    Boolean,
}

// -------------------------------------------------------------------
// SysctlEntry
// -------------------------------------------------------------------

/// A single sysctl parameter entry.
///
/// Stores the dotted path, type, current value, and constraints.
/// Integer entries may have `min` and `max` bounds; string entries
/// store their value in a fixed-size byte buffer.
#[derive(Debug, Clone, Copy)]
pub struct SysctlEntry {
    /// Dotted path (e.g., "kernel.hostname").
    path: [u8; MAX_PATH_LEN],
    /// Valid length of `path`.
    path_len: usize,
    /// Data type of this parameter.
    pub value_type: SysctlType,
    /// Integer value (used when `value_type` is `Integer` or `Boolean`).
    pub int_value: i64,
    /// String value buffer (used when `value_type` is `String`).
    str_value: [u8; MAX_STR_VALUE_LEN],
    /// Valid length of `str_value`.
    str_value_len: usize,
    /// Minimum allowed integer value (inclusive).
    pub min: i64,
    /// Maximum allowed integer value (inclusive).
    pub max: i64,
    /// Whether this entry is read-only.
    pub read_only: bool,
    /// Whether this slot is occupied.
    in_use: bool,
}

/// An empty sysctl entry used for array initialization.
const EMPTY_SYSCTL_ENTRY: SysctlEntry = SysctlEntry {
    path: [0; MAX_PATH_LEN],
    path_len: 0,
    value_type: SysctlType::Integer,
    int_value: 0,
    str_value: [0; MAX_STR_VALUE_LEN],
    str_value_len: 0,
    min: i64::MIN,
    max: i64::MAX,
    read_only: false,
    in_use: false,
};

impl SysctlEntry {
    /// Create a new integer sysctl entry.
    pub fn new_integer(
        path: &[u8],
        value: i64,
        min: i64,
        max: i64,
        read_only: bool,
    ) -> Result<Self> {
        if path.is_empty() || path.len() > MAX_PATH_LEN {
            return Err(Error::InvalidArgument);
        }
        if value < min || value > max {
            return Err(Error::InvalidArgument);
        }
        let mut entry = EMPTY_SYSCTL_ENTRY;
        let plen = path.len().min(MAX_PATH_LEN);
        entry.path[..plen].copy_from_slice(&path[..plen]);
        entry.path_len = plen;
        entry.value_type = SysctlType::Integer;
        entry.int_value = value;
        entry.min = min;
        entry.max = max;
        entry.read_only = read_only;
        entry.in_use = true;
        Ok(entry)
    }

    /// Create a new string sysctl entry.
    pub fn new_string(path: &[u8], value: &[u8], read_only: bool) -> Result<Self> {
        if path.is_empty() || path.len() > MAX_PATH_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut entry = EMPTY_SYSCTL_ENTRY;
        let plen = path.len().min(MAX_PATH_LEN);
        entry.path[..plen].copy_from_slice(&path[..plen]);
        entry.path_len = plen;
        entry.value_type = SysctlType::String;
        let vlen = value.len().min(MAX_STR_VALUE_LEN);
        entry.str_value[..vlen].copy_from_slice(&value[..vlen]);
        entry.str_value_len = vlen;
        entry.read_only = read_only;
        entry.in_use = true;
        Ok(entry)
    }

    /// Create a new boolean sysctl entry.
    pub fn new_boolean(path: &[u8], value: bool, read_only: bool) -> Result<Self> {
        if path.is_empty() || path.len() > MAX_PATH_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut entry = EMPTY_SYSCTL_ENTRY;
        let plen = path.len().min(MAX_PATH_LEN);
        entry.path[..plen].copy_from_slice(&path[..plen]);
        entry.path_len = plen;
        entry.value_type = SysctlType::Boolean;
        entry.int_value = if value { 1 } else { 0 };
        entry.min = 0;
        entry.max = 1;
        entry.read_only = read_only;
        entry.in_use = true;
        Ok(entry)
    }

    /// Return the path as a byte slice.
    pub fn path(&self) -> &[u8] {
        &self.path[..self.path_len]
    }

    /// Return the string value as a byte slice.
    pub fn str_value(&self) -> &[u8] {
        &self.str_value[..self.str_value_len]
    }

    /// Return the boolean value, or `None` if this is not a boolean entry.
    pub fn bool_value(&self) -> Option<bool> {
        if self.value_type == SysctlType::Boolean {
            Some(self.int_value != 0)
        } else {
            None
        }
    }

    /// Set the integer value, respecting min/max bounds.
    pub fn set_int(&mut self, value: i64) -> Result<()> {
        if self.read_only {
            return Err(Error::PermissionDenied);
        }
        if self.value_type != SysctlType::Integer {
            return Err(Error::InvalidArgument);
        }
        if value < self.min || value > self.max {
            return Err(Error::InvalidArgument);
        }
        self.int_value = value;
        Ok(())
    }

    /// Set the string value.
    pub fn set_str(&mut self, value: &[u8]) -> Result<()> {
        if self.read_only {
            return Err(Error::PermissionDenied);
        }
        if self.value_type != SysctlType::String {
            return Err(Error::InvalidArgument);
        }
        let vlen = value.len().min(MAX_STR_VALUE_LEN);
        self.str_value = [0; MAX_STR_VALUE_LEN];
        self.str_value[..vlen].copy_from_slice(&value[..vlen]);
        self.str_value_len = vlen;
        Ok(())
    }

    /// Set the boolean value.
    pub fn set_bool(&mut self, value: bool) -> Result<()> {
        if self.read_only {
            return Err(Error::PermissionDenied);
        }
        if self.value_type != SysctlType::Boolean {
            return Err(Error::InvalidArgument);
        }
        self.int_value = if value { 1 } else { 0 };
        Ok(())
    }
}

// -------------------------------------------------------------------
// SysctlTable
// -------------------------------------------------------------------

/// Table of sysctl entries, supporting registration, lookup, and
/// prefix-based listing.
pub struct SysctlTable {
    /// Entry storage.
    entries: [SysctlEntry; MAX_SYSCTL_ENTRIES],
    /// Number of registered entries.
    count: usize,
}

impl Default for SysctlTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SysctlTable {
    /// Create an empty sysctl table.
    pub const fn new() -> Self {
        Self {
            entries: [EMPTY_SYSCTL_ENTRY; MAX_SYSCTL_ENTRIES],
            count: 0,
        }
    }

    /// Register a new sysctl entry.
    ///
    /// Returns the slot index on success, or an error if the table
    /// is full or the path already exists.
    pub fn register(&mut self, entry: SysctlEntry) -> Result<usize> {
        if self.count >= MAX_SYSCTL_ENTRIES {
            return Err(Error::OutOfMemory);
        }

        // Check for duplicate path.
        let new_path = entry.path();
        for e in &self.entries {
            if e.in_use && e.path() == new_path {
                return Err(Error::AlreadyExists);
            }
        }

        // Find a free slot.
        for (idx, slot) in self.entries.iter_mut().enumerate() {
            if !slot.in_use {
                *slot = entry;
                self.count += 1;
                return Ok(idx);
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Unregister a sysctl entry by path.
    pub fn unregister(&mut self, path: &[u8]) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if slot.in_use && slot.path() == path {
                *slot = EMPTY_SYSCTL_ENTRY;
                self.count = self.count.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Read a sysctl entry by exact path.
    pub fn read(&self, path: &[u8]) -> Result<&SysctlEntry> {
        for entry in &self.entries {
            if entry.in_use && entry.path() == path {
                return Ok(entry);
            }
        }
        Err(Error::NotFound)
    }

    /// Get a mutable reference to a sysctl entry by exact path.
    pub fn write(&mut self, path: &[u8]) -> Result<&mut SysctlEntry> {
        for entry in self.entries.iter_mut() {
            if entry.in_use && entry.path() == path {
                if entry.read_only {
                    return Err(Error::PermissionDenied);
                }
                return Ok(entry);
            }
        }
        Err(Error::NotFound)
    }

    /// List entries whose path starts with the given prefix.
    ///
    /// Copies matching entries into `buf` and returns the number
    /// of entries copied.
    pub fn list_by_prefix<'a>(&'a self, prefix: &[u8], buf: &mut [&'a SysctlEntry]) -> usize {
        let mut copied = 0;
        for entry in &self.entries {
            if copied >= buf.len() {
                break;
            }
            if entry.in_use && entry.path().starts_with(prefix) {
                buf[copied] = entry;
                copied += 1;
            }
        }
        copied
    }

    /// Return the number of registered entries.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl core::fmt::Debug for SysctlTable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SysctlTable")
            .field("count", &self.count)
            .field("capacity", &MAX_SYSCTL_ENTRIES)
            .finish()
    }
}

// -------------------------------------------------------------------
// SysctlRegistry
// -------------------------------------------------------------------

/// Global sysctl registry wrapping a `SysctlTable`.
///
/// Provides a convenient interface for kernel subsystems to
/// register, query, and modify runtime parameters.
pub struct SysctlRegistry {
    /// The backing sysctl table.
    pub table: SysctlTable,
}

impl Default for SysctlRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SysctlRegistry {
    /// Create a new, empty sysctl registry.
    pub const fn new() -> Self {
        Self {
            table: SysctlTable::new(),
        }
    }

    /// Register a sysctl entry.
    pub fn register(&mut self, entry: SysctlEntry) -> Result<usize> {
        self.table.register(entry)
    }

    /// Unregister a sysctl entry by path.
    pub fn unregister(&mut self, path: &[u8]) -> Result<()> {
        self.table.unregister(path)
    }

    /// Get the value of an integer sysctl.
    pub fn get_int(&self, path: &[u8]) -> Result<i64> {
        let entry = self.table.read(path)?;
        if entry.value_type != SysctlType::Integer {
            return Err(Error::InvalidArgument);
        }
        Ok(entry.int_value)
    }

    /// Get the value of a string sysctl as a byte slice.
    pub fn get_str(&self, path: &[u8]) -> Result<&[u8]> {
        let entry = self.table.read(path)?;
        if entry.value_type != SysctlType::String {
            return Err(Error::InvalidArgument);
        }
        Ok(entry.str_value())
    }

    /// Get the value of a boolean sysctl.
    pub fn get_bool(&self, path: &[u8]) -> Result<bool> {
        let entry = self.table.read(path)?;
        match entry.bool_value() {
            Some(v) => Ok(v),
            None => Err(Error::InvalidArgument),
        }
    }

    /// Set the value of an integer sysctl.
    pub fn set_int(&mut self, path: &[u8], value: i64) -> Result<()> {
        let entry = self.table.write(path)?;
        entry.set_int(value)
    }

    /// Set the value of a string sysctl.
    pub fn set_str(&mut self, path: &[u8], value: &[u8]) -> Result<()> {
        let entry = self.table.write(path)?;
        entry.set_str(value)
    }

    /// Set the value of a boolean sysctl.
    pub fn set_bool(&mut self, path: &[u8], value: bool) -> Result<()> {
        let entry = self.table.write(path)?;
        entry.set_bool(value)
    }

    /// List entries by prefix.
    pub fn list<'a>(&'a self, prefix: &[u8], buf: &mut [&'a SysctlEntry]) -> usize {
        self.table.list_by_prefix(prefix, buf)
    }

    /// Return the number of registered entries.
    pub fn count(&self) -> usize {
        self.table.count()
    }
}

impl core::fmt::Debug for SysctlRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SysctlRegistry")
            .field("table", &self.table)
            .finish()
    }
}
