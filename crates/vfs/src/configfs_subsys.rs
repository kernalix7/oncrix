// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! configfs subsystem management.
//!
//! Implements the configfs in-kernel API for subsystems and items.
//! configfs is a RAM-based filesystem that allows kernel subsystems to
//! expose configurable objects to userspace via the filesystem interface.
//!
//! # Components
//!
//! - [`ConfigSubsystem`] — a configfs subsystem with name and item type
//! - [`ConfigItem`] — a configurable item within a subsystem
//! - [`ConfigAttribute`] — an attribute (show/store) on a config item
//! - `subsys_register` / `subsys_unregister` — subsystem lifecycle
//! - `mkdir_item` / `rmdir_item` — item creation/deletion
//!
//! # Reference
//!
//! Linux `fs/configfs/`, `include/linux/configfs.h`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of registered subsystems.
const MAX_SUBSYSTEMS: usize = 32;

/// Maximum items per subsystem.
const MAX_ITEMS_PER_SUBSYS: usize = 64;

/// Maximum attributes per item.
const MAX_ATTRIBUTES: usize = 16;

/// Maximum name length.
const MAX_NAME_LEN: usize = 64;

/// Maximum attribute value size.
const MAX_ATTR_VALUE: usize = 256;

// ---------------------------------------------------------------------------
// Attribute
// ---------------------------------------------------------------------------

/// A single configfs attribute (file) on a config item.
#[derive(Debug, Clone)]
pub struct ConfigAttribute {
    /// Attribute name.
    pub name: [u8; MAX_NAME_LEN],
    /// Valid bytes in `name`.
    pub name_len: usize,
    /// Attribute mode (0o644 = rw for owner, r for others).
    pub mode: u16,
    /// Current stored value.
    pub value: [u8; MAX_ATTR_VALUE],
    /// Valid bytes in `value`.
    pub value_len: usize,
    /// Whether this attribute is read-only.
    pub read_only: bool,
}

impl ConfigAttribute {
    /// Creates a new read-write attribute.
    pub fn new(name: &[u8], mode: u16) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut n_buf = [0u8; MAX_NAME_LEN];
        n_buf[..name.len()].copy_from_slice(name);
        Ok(Self {
            name: n_buf,
            name_len: name.len(),
            mode,
            value: [0u8; MAX_ATTR_VALUE],
            value_len: 0,
            read_only: mode & 0o200 == 0,
        })
    }

    /// Returns the attribute name as bytes.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns the value as bytes.
    pub fn value_bytes(&self) -> &[u8] {
        &self.value[..self.value_len]
    }

    /// Shows (reads) the attribute value into `out`. Returns bytes written.
    pub fn show(&self, out: &mut [u8]) -> usize {
        let len = self.value_len.min(out.len());
        out[..len].copy_from_slice(&self.value[..len]);
        len
    }

    /// Stores (writes) a new value for the attribute.
    pub fn store(&mut self, data: &[u8]) -> Result<()> {
        if self.read_only {
            return Err(Error::PermissionDenied);
        }
        if data.len() > MAX_ATTR_VALUE {
            return Err(Error::InvalidArgument);
        }
        self.value[..data.len()].copy_from_slice(data);
        self.value_len = data.len();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Config item
// ---------------------------------------------------------------------------

/// A single configurable item within a configfs subsystem.
#[derive(Debug)]
pub struct ConfigItem {
    /// Item name (the directory name in configfs).
    pub name: [u8; MAX_NAME_LEN],
    /// Valid bytes in `name`.
    pub name_len: usize,
    /// Attributes for this item.
    pub attributes: [Option<ConfigAttribute>; MAX_ATTRIBUTES],
    /// Number of attributes.
    pub attr_count: usize,
    /// Whether this item is active.
    pub active: bool,
    /// Subsystem index this item belongs to.
    pub subsys_index: usize,
    /// Unique item ID.
    pub item_id: u32,
}

impl ConfigItem {
    /// Creates a new config item.
    pub fn new(name: &[u8], subsys_index: usize, item_id: u32) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut n_buf = [0u8; MAX_NAME_LEN];
        n_buf[..name.len()].copy_from_slice(name);
        Ok(Self {
            name: n_buf,
            name_len: name.len(),
            attributes: core::array::from_fn(|_| None),
            attr_count: 0,
            active: true,
            subsys_index,
            item_id,
        })
    }

    /// Returns the item name as bytes.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Adds an attribute to this item.
    pub fn add_attribute(&mut self, attr: ConfigAttribute) -> Result<()> {
        if self.attr_count >= MAX_ATTRIBUTES {
            return Err(Error::OutOfMemory);
        }
        for slot in &mut self.attributes {
            if slot.is_none() {
                *slot = Some(attr);
                self.attr_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns a reference to an attribute by name.
    pub fn get_attr(&self, name: &[u8]) -> Option<&ConfigAttribute> {
        self.attributes
            .iter()
            .flatten()
            .find(|a| a.name_bytes() == name)
    }

    /// Returns a mutable reference to an attribute by name.
    pub fn get_attr_mut(&mut self, name: &[u8]) -> Option<&mut ConfigAttribute> {
        self.attributes
            .iter_mut()
            .flatten()
            .find(|a| a.name_bytes() == name)
    }
}

// ---------------------------------------------------------------------------
// Item type (operations)
// ---------------------------------------------------------------------------

/// Describes the type of items that can be created in a subsystem.
#[derive(Debug, Clone, Copy)]
pub struct ItemType {
    /// Whether items of this type can have sub-groups.
    pub has_groups: bool,
    /// Default permission mode for items.
    pub item_mode: u16,
    /// Default permission mode for attributes.
    pub attr_mode: u16,
}

impl ItemType {
    /// Creates a simple item type.
    pub const fn simple() -> Self {
        Self {
            has_groups: false,
            item_mode: 0o755,
            attr_mode: 0o644,
        }
    }
}

// ---------------------------------------------------------------------------
// Config subsystem
// ---------------------------------------------------------------------------

/// A configfs subsystem.
pub struct ConfigSubsystem {
    /// Subsystem name.
    pub name: [u8; MAX_NAME_LEN],
    /// Valid bytes in `name`.
    pub name_len: usize,
    /// Item type specification.
    pub item_type: ItemType,
    /// Items within this subsystem.
    items: [Option<ConfigItem>; MAX_ITEMS_PER_SUBSYS],
    /// Number of items.
    item_count: usize,
    /// Whether this subsystem is registered.
    pub registered: bool,
    /// Subsystem index in the registry.
    pub index: usize,
    /// Next item ID.
    next_item_id: u32,
}

impl ConfigSubsystem {
    /// Creates a new configfs subsystem.
    pub fn new(name: &[u8], item_type: ItemType, index: usize) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut n_buf = [0u8; MAX_NAME_LEN];
        n_buf[..name.len()].copy_from_slice(name);
        Ok(Self {
            name: n_buf,
            name_len: name.len(),
            item_type,
            items: core::array::from_fn(|_| None),
            item_count: 0,
            registered: false,
            index,
            next_item_id: 1,
        })
    }

    /// Returns the subsystem name as bytes.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns the number of items.
    pub fn item_count(&self) -> usize {
        self.item_count
    }

    /// Creates a new item in this subsystem.
    pub fn mkdir_item(&mut self, name: &[u8]) -> Result<u32> {
        if self.item_count >= MAX_ITEMS_PER_SUBSYS {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate name.
        for slot in self.items[..].iter().flatten() {
            if slot.name_bytes() == name && slot.active {
                return Err(Error::AlreadyExists);
            }
        }
        let id = self.next_item_id;
        self.next_item_id += 1;
        let item = ConfigItem::new(name, self.index, id)?;
        for slot in &mut self.items {
            if slot.is_none() {
                *slot = Some(item);
                self.item_count += 1;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Removes an item from this subsystem.
    pub fn rmdir_item(&mut self, name: &[u8]) -> Result<()> {
        for slot in &mut self.items {
            if slot.as_ref().map(|i| i.name_bytes() == name && i.active) == Some(true) {
                if let Some(item) = slot.as_mut() {
                    item.active = false;
                }
                *slot = None;
                self.item_count = self.item_count.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a reference to an item by name.
    pub fn get_item(&self, name: &[u8]) -> Option<&ConfigItem> {
        self.items
            .iter()
            .flatten()
            .find(|i| i.name_bytes() == name && i.active)
    }

    /// Returns a mutable reference to an item by name.
    pub fn get_item_mut(&mut self, name: &[u8]) -> Option<&mut ConfigItem> {
        self.items
            .iter_mut()
            .flatten()
            .find(|i| i.name_bytes() == name && i.active)
    }

    /// Reads an item attribute. Returns bytes written.
    pub fn attr_show(&self, item_name: &[u8], attr_name: &[u8], out: &mut [u8]) -> Result<usize> {
        let item = self.get_item(item_name).ok_or(Error::NotFound)?;
        let attr = item.get_attr(attr_name).ok_or(Error::NotFound)?;
        Ok(attr.show(out))
    }

    /// Writes an item attribute.
    pub fn attr_store(&mut self, item_name: &[u8], attr_name: &[u8], data: &[u8]) -> Result<()> {
        let item = self.get_item_mut(item_name).ok_or(Error::NotFound)?;
        let attr = item.get_attr_mut(attr_name).ok_or(Error::NotFound)?;
        attr.store(data)
    }
}

// ---------------------------------------------------------------------------
// Subsystem registry
// ---------------------------------------------------------------------------

/// Global configfs subsystem registry.
pub struct ConfigfsRegistry {
    /// Registered subsystems.
    subsystems: [Option<ConfigSubsystem>; MAX_SUBSYSTEMS],
    /// Number of registered subsystems.
    count: usize,
}

impl ConfigfsRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            subsystems: core::array::from_fn(|_| None),
            count: 0,
        }
    }

    /// Returns the number of subsystems.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Registers a new subsystem.
    pub fn subsys_register(&mut self, mut subsys: ConfigSubsystem) -> Result<usize> {
        if self.count >= MAX_SUBSYSTEMS {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate name.
        for slot in self.subsystems[..].iter().flatten() {
            if slot.name_bytes() == subsys.name_bytes() {
                return Err(Error::AlreadyExists);
            }
        }
        for (i, slot) in self.subsystems.iter_mut().enumerate() {
            if slot.is_none() {
                subsys.index = i;
                subsys.registered = true;
                *slot = Some(subsys);
                self.count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters a subsystem by name.
    pub fn subsys_unregister(&mut self, name: &[u8]) -> Result<()> {
        for slot in &mut self.subsystems {
            if slot.as_ref().map(|s| s.name_bytes() == name) == Some(true) {
                let subsys = slot.as_ref().unwrap();
                if subsys.item_count() > 0 {
                    return Err(Error::Busy);
                }
                *slot = None;
                self.count = self.count.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a reference to a subsystem by name.
    pub fn find(&self, name: &[u8]) -> Option<&ConfigSubsystem> {
        self.subsystems
            .iter()
            .flatten()
            .find(|s| s.name_bytes() == name)
    }

    /// Returns a mutable reference to a subsystem by name.
    pub fn find_mut(&mut self, name: &[u8]) -> Option<&mut ConfigSubsystem> {
        self.subsystems
            .iter_mut()
            .flatten()
            .find(|s| s.name_bytes() == name)
    }
}

impl Default for ConfigfsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Top-level operations
// ---------------------------------------------------------------------------

/// Creates an item directory within a subsystem.
pub fn mkdir_item(registry: &mut ConfigfsRegistry, subsys: &[u8], item: &[u8]) -> Result<u32> {
    registry
        .find_mut(subsys)
        .ok_or(Error::NotFound)?
        .mkdir_item(item)
}

/// Removes an item directory from a subsystem.
pub fn rmdir_item(registry: &mut ConfigfsRegistry, subsys: &[u8], item: &[u8]) -> Result<()> {
    registry
        .find_mut(subsys)
        .ok_or(Error::NotFound)?
        .rmdir_item(item)
}
