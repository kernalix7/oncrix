// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! configfs attribute implementation.
//!
//! configfs is a RAM-based filesystem that exports kernel objects and allows
//! user-space to create, modify, and delete them via standard filesystem
//! operations. Each configfs item has a set of attributes whose values are
//! read and written through `show`/`store` callbacks.
//!
//! # Design
//!
//! - [`ConfigAttribute`] — an attribute with name, show, and store callbacks
//! - [`BinaryConfigAttribute`] — binary attribute with a large data buffer
//! - [`ConfigItem`] — a configfs item (directory) with its attribute set
//! - `configfs_create_file` — register an attribute on an item
//!
//! # References
//!
//! - Linux `fs/configfs/`, `include/linux/configfs.h`
//! - Linux `Documentation/filesystems/configfs.rst`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum length of an attribute name.
const ATTR_NAME_LEN: usize = 64;

/// Maximum number of attributes per configfs item.
const MAX_ATTRS_PER_ITEM: usize = 16;

/// Maximum value buffer size for a textual attribute (4 KiB = one page).
pub const ATTR_VALUE_PAGE_SIZE: usize = 4096;

/// Maximum data buffer size for a binary attribute (64 KiB).
pub const BINARY_ATTR_BUF_SIZE: usize = 65536;

/// Maximum number of configfs items in the system.
const MAX_CONFIGFS_ITEMS: usize = 64;

/// Maximum item name length.
const ITEM_NAME_LEN: usize = 64;

// ---------------------------------------------------------------------------
// ConfigAttribute
// ---------------------------------------------------------------------------

/// A textual configfs attribute file.
///
/// The `show` callback serializes the current value into a page-sized buffer.
/// The `store` callback parses and applies user input.
pub struct ConfigAttribute {
    /// Attribute file name (e.g., `"timeout"`).
    pub name: [u8; ATTR_NAME_LEN],
    /// Length of `name`.
    pub name_len: usize,
    /// POSIX mode bits (typically 0o644).
    pub mode: u16,
    /// Whether this attribute slot is populated.
    pub active: bool,
    /// Current value buffer (textual, page-aligned).
    pub value: [u8; ATTR_VALUE_PAGE_SIZE],
    /// Number of valid bytes in `value`.
    pub value_len: usize,
}

impl ConfigAttribute {
    /// Create an empty attribute.
    pub const fn empty() -> Self {
        Self {
            name: [0u8; ATTR_NAME_LEN],
            name_len: 0,
            mode: 0o644,
            active: false,
            value: [0u8; ATTR_VALUE_PAGE_SIZE],
            value_len: 0,
        }
    }

    /// Return the attribute name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the attribute value as a byte slice (show callback result).
    pub fn show(&self) -> &[u8] {
        &self.value[..self.value_len]
    }

    /// Apply user-supplied data (store callback).
    ///
    /// Returns `Err(InvalidArgument)` if `data` is longer than the page size.
    pub fn store(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > ATTR_VALUE_PAGE_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.value[..data.len()].copy_from_slice(data);
        self.value_len = data.len();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BinaryConfigAttribute
// ---------------------------------------------------------------------------

/// A binary configfs attribute with a large data buffer.
///
/// Binary attributes bypass the textual show/store path and allow arbitrary
/// binary blobs up to `BINARY_ATTR_BUF_SIZE` bytes.
pub struct BinaryConfigAttribute {
    /// Attribute file name.
    pub name: [u8; ATTR_NAME_LEN],
    /// Length of `name`.
    pub name_len: usize,
    /// POSIX mode bits.
    pub mode: u16,
    /// Whether this slot is in use.
    pub active: bool,
    /// Binary data buffer.
    pub data: [u8; BINARY_ATTR_BUF_SIZE],
    /// Number of valid bytes in `data`.
    pub data_len: usize,
}

impl BinaryConfigAttribute {
    /// Create an empty binary attribute.
    pub fn empty() -> Self {
        Self {
            name: [0u8; ATTR_NAME_LEN],
            name_len: 0,
            mode: 0o644,
            active: false,
            data: [0u8; BINARY_ATTR_BUF_SIZE],
            data_len: 0,
        }
    }

    /// Return the attribute name.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the binary data.
    pub fn read_data(&self, off: usize, buf: &mut [u8]) -> Result<usize> {
        if off >= self.data_len {
            return Ok(0);
        }
        let avail = self.data_len - off;
        let n = buf.len().min(avail);
        buf[..n].copy_from_slice(&self.data[off..off + n]);
        Ok(n)
    }

    /// Write `data` into the binary attribute buffer at `off`.
    pub fn write_data(&mut self, off: usize, data: &[u8]) -> Result<usize> {
        if off + data.len() > BINARY_ATTR_BUF_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.data[off..off + data.len()].copy_from_slice(data);
        let end = off + data.len();
        if end > self.data_len {
            self.data_len = end;
        }
        Ok(data.len())
    }
}

// ---------------------------------------------------------------------------
// ConfigItem
// ---------------------------------------------------------------------------

/// A configfs item (directory) with its attribute set.
pub struct ConfigItem {
    /// Item name (the directory name in configfs).
    pub name: [u8; ITEM_NAME_LEN],
    /// Length of `name`.
    pub name_len: usize,
    /// Whether this item slot is occupied.
    pub active: bool,
    /// Textual attributes.
    attrs: [ConfigAttribute; MAX_ATTRS_PER_ITEM],
    /// Number of textual attributes.
    attr_count: usize,
}

impl ConfigItem {
    /// Create an empty config item.
    pub const fn empty() -> Self {
        Self {
            name: [0u8; ITEM_NAME_LEN],
            name_len: 0,
            active: false,
            attrs: [const { ConfigAttribute::empty() }; MAX_ATTRS_PER_ITEM],
            attr_count: 0,
        }
    }

    /// Set the item name.
    pub fn set_name(&mut self, name: &[u8]) -> Result<()> {
        if name.len() > ITEM_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        self.name[..name.len()].copy_from_slice(name);
        self.name_len = name.len();
        Ok(())
    }

    /// Return the item name.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Register an attribute on this item.
    ///
    /// Returns `Err(OutOfMemory)` if no slots remain.
    /// Returns `Err(AlreadyExists)` if an attribute with the same name exists.
    pub fn configfs_create_file(&mut self, name: &[u8], mode: u16) -> Result<()> {
        if name.len() > ATTR_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        // Check for duplicate.
        for a in &self.attrs[..self.attr_count] {
            if a.active && a.name_bytes() == name {
                return Err(Error::AlreadyExists);
            }
        }
        if self.attr_count >= MAX_ATTRS_PER_ITEM {
            return Err(Error::OutOfMemory);
        }
        let slot = &mut self.attrs[self.attr_count];
        slot.name[..name.len()].copy_from_slice(name);
        slot.name_len = name.len();
        slot.mode = mode;
        slot.value_len = 0;
        slot.active = true;
        self.attr_count += 1;
        Ok(())
    }

    /// Remove the attribute named `name`.
    pub fn remove_attr(&mut self, name: &[u8]) -> Result<()> {
        let idx = self.attrs[..self.attr_count]
            .iter()
            .position(|a| a.active && a.name_bytes() == name)
            .ok_or(Error::NotFound)?;
        self.attrs[idx] = ConfigAttribute::empty();
        // Compact: swap with last.
        if idx + 1 < self.attr_count {
            self.attrs.swap(idx, self.attr_count - 1);
        }
        self.attr_count -= 1;
        Ok(())
    }

    /// Read the value of attribute `name`.
    pub fn read_attr(&self, name: &[u8]) -> Result<&[u8]> {
        self.attrs[..self.attr_count]
            .iter()
            .find(|a| a.active && a.name_bytes() == name)
            .map(|a| a.show())
            .ok_or(Error::NotFound)
    }

    /// Write `data` to attribute `name`.
    pub fn write_attr(&mut self, name: &[u8], data: &[u8]) -> Result<()> {
        self.attrs[..self.attr_count]
            .iter_mut()
            .find(|a| a.active && a.name_bytes() == name)
            .ok_or(Error::NotFound)?
            .store(data)
    }

    /// Return the number of attributes.
    pub fn attr_count(&self) -> usize {
        self.attr_count
    }
}

// ---------------------------------------------------------------------------
// ConfigfsRegistry
// ---------------------------------------------------------------------------

/// Registry of all configfs items in the system.
pub struct ConfigfsRegistry {
    items: [ConfigItem; MAX_CONFIGFS_ITEMS],
    count: usize,
}

impl ConfigfsRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            items: [const { ConfigItem::empty() }; MAX_CONFIGFS_ITEMS],
            count: 0,
        }
    }

    /// Create a new configfs item with the given name.
    ///
    /// Returns its index or `Err(OutOfMemory)` if full.
    pub fn create_item(&mut self, name: &[u8]) -> Result<usize> {
        if self.count >= MAX_CONFIGFS_ITEMS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        let item = &mut self.items[idx];
        item.set_name(name)?;
        item.active = true;
        self.count += 1;
        Ok(idx)
    }

    /// Get a mutable reference to item at `idx`.
    pub fn item_mut(&mut self, idx: usize) -> Result<&mut ConfigItem> {
        if idx >= self.count || !self.items[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&mut self.items[idx])
    }

    /// Get an immutable reference to item at `idx`.
    pub fn item(&self, idx: usize) -> Result<&ConfigItem> {
        if idx >= self.count || !self.items[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&self.items[idx])
    }

    /// Delete the item at `idx`.
    pub fn delete_item(&mut self, idx: usize) -> Result<()> {
        if idx >= self.count || !self.items[idx].active {
            return Err(Error::NotFound);
        }
        self.items[idx] = ConfigItem::empty();
        if idx + 1 < self.count {
            self.items.swap(idx, self.count - 1);
        }
        self.count -= 1;
        Ok(())
    }

    /// Return the number of active items.
    pub fn item_count(&self) -> usize {
        self.count
    }
}
