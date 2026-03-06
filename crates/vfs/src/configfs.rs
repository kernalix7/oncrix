// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! configfs — Configuration filesystem.
//!
//! Provides a RAM-based filesystem for kernel object configuration.
//! User space creates, modifies, and destroys kernel objects by
//! creating directories (`mkdir`/`rmdir`) and reading/writing
//! attribute files within the mounted configfs tree.
//!
//! # Design
//!
//! - [`ConfigAttr`] — a single attribute with name, value, and show/store callbacks
//! - [`ConfigItem`] — a configuration item with up to 16 attributes
//! - [`ConfigGroup`] — a group containing items and nested sub-groups
//! - [`ConfigSubsystem`] — a top-level subsystem with a root group
//! - [`ConfigFs`] — filesystem instance (8 subsystem slots)
//! - [`ConfigRegistry`] — global registry for subsystem registration
//!
//! # Usage
//!
//! ```text
//! mount -t configfs none /sys/kernel/config
//! mkdir /sys/kernel/config/mysubsystem/myobject
//! echo "value" > /sys/kernel/config/mysubsystem/myobject/attr
//! ```
//!
//! Reference: Linux `fs/configfs/`, `Documentation/filesystems/configfs.rst`.

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Maximum attribute name length.
const ATTR_NAME_LEN: usize = 64;

/// Maximum attribute value length.
const ATTR_VALUE_LEN: usize = 256;

/// Maximum attributes per config item.
const MAX_ATTRS_PER_ITEM: usize = 16;

/// Maximum items per config group.
const MAX_ITEMS_PER_GROUP: usize = 32;

/// Maximum child sub-groups per group.
const MAX_CHILDREN_PER_GROUP: usize = 8;

/// Maximum default attributes per group.
const MAX_DEFAULT_ATTRS: usize = 8;

/// Maximum subsystems per configfs instance.
const MAX_SUBSYSTEMS: usize = 8;

/// Maximum name length for items, groups, and subsystems.
const MAX_NAME_LEN: usize = 64;

/// Maximum registered subsystems in the global registry.
const MAX_REGISTRY_ENTRIES: usize = 8;

// ── ConfigAttr ──────────────────────────────────────────────────

/// A single configuration attribute.
///
/// Attributes are files within a configfs item directory. Each
/// attribute has a name, a value buffer, and a writable flag that
/// controls whether user-space can modify it.
#[derive(Debug, Clone)]
pub struct ConfigAttr {
    /// Attribute name.
    pub name: [u8; ATTR_NAME_LEN],
    /// Name length.
    pub name_len: u8,
    /// Attribute value.
    pub value: [u8; ATTR_VALUE_LEN],
    /// Value length.
    pub value_len: u16,
    /// Whether this attribute is writable.
    pub writable: bool,
    /// Index into a function pointer table for the show callback.
    pub show_cb: u16,
    /// Index into a function pointer table for the store callback.
    pub store_cb: u16,
    /// Whether this attribute slot is active.
    pub active: bool,
}

impl ConfigAttr {
    /// Create an empty (inactive) attribute.
    const fn empty() -> Self {
        Self {
            name: [0; ATTR_NAME_LEN],
            name_len: 0,
            value: [0; ATTR_VALUE_LEN],
            value_len: 0,
            writable: false,
            show_cb: 0,
            store_cb: 0,
            active: false,
        }
    }

    /// Create a new attribute with the given name.
    fn new(name: &str, writable: bool) -> Result<Self> {
        let name_bytes = name.as_bytes();
        if name_bytes.is_empty() || name_bytes.len() > ATTR_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut attr = Self::empty();
        attr.name[..name_bytes.len()].copy_from_slice(name_bytes);
        attr.name_len = name_bytes.len() as u8;
        attr.writable = writable;
        attr.active = true;
        Ok(attr)
    }

    /// Read the attribute value into a buffer.
    pub fn show(&self, buf: &mut [u8]) -> Result<usize> {
        if !self.active {
            return Err(Error::NotFound);
        }
        let len = (self.value_len as usize).min(buf.len());
        buf[..len].copy_from_slice(&self.value[..len]);
        Ok(len)
    }

    /// Write a new value to the attribute.
    pub fn store(&mut self, data: &[u8]) -> Result<usize> {
        if !self.active {
            return Err(Error::NotFound);
        }
        if !self.writable {
            return Err(Error::PermissionDenied);
        }
        let len = data.len().min(ATTR_VALUE_LEN);
        self.value[..len].copy_from_slice(&data[..len]);
        self.value_len = len as u16;
        Ok(len)
    }

    /// Return the attribute name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

// ── ConfigItem ──────────────────────────────────────────────────

/// A configuration item (directory) containing attributes.
///
/// Items are created by `mkdir` within a configfs group and
/// represent individual kernel objects being configured.
#[derive(Debug, Clone)]
pub struct ConfigItem {
    /// Item name.
    pub name: [u8; MAX_NAME_LEN],
    /// Name length.
    pub name_len: u8,
    /// Attributes for this item.
    pub attrs: [ConfigAttr; MAX_ATTRS_PER_ITEM],
    /// Number of active attributes.
    pub attr_count: usize,
    /// Whether this item slot is active.
    pub active: bool,
}

impl ConfigItem {
    /// Create an empty (inactive) item.
    const fn empty() -> Self {
        const EMPTY_ATTR: ConfigAttr = ConfigAttr::empty();
        Self {
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            attrs: [EMPTY_ATTR; MAX_ATTRS_PER_ITEM],
            attr_count: 0,
            active: false,
        }
    }

    /// Create a new item with the given name.
    fn new(name: &str) -> Result<Self> {
        let name_bytes = name.as_bytes();
        if name_bytes.is_empty() || name_bytes.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut item = Self::empty();
        item.name[..name_bytes.len()].copy_from_slice(name_bytes);
        item.name_len = name_bytes.len() as u8;
        item.active = true;
        Ok(item)
    }

    /// Add a new attribute to this item.
    pub fn add_attr(&mut self, name: &str, writable: bool) -> Result<usize> {
        if self.attr_count >= MAX_ATTRS_PER_ITEM {
            return Err(Error::OutOfMemory);
        }
        let name_bytes = name.as_bytes();
        // Check for duplicates.
        for attr in &self.attrs {
            if attr.active && attr.name_bytes() == name_bytes {
                return Err(Error::AlreadyExists);
            }
        }
        let attr = ConfigAttr::new(name, writable)?;
        for (idx, slot) in self.attrs.iter_mut().enumerate() {
            if !slot.active {
                *slot = attr;
                self.attr_count += 1;
                return Ok(idx);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find an attribute by name, returning its index.
    pub fn find_attr(&self, name: &str) -> Option<usize> {
        let name_bytes = name.as_bytes();
        self.attrs
            .iter()
            .position(|a| a.active && a.name_bytes() == name_bytes)
    }

    /// Return the item name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

// ── ConfigGroup ─────────────────────────────────────────────────

/// A configuration group — a directory that can contain items and
/// nested sub-groups.
///
/// Groups define the structure of the configfs tree. Creating a
/// directory within a group creates a new item with the group's
/// default attributes.
#[derive(Debug, Clone)]
pub struct ConfigGroup {
    /// Group name.
    pub name: [u8; MAX_NAME_LEN],
    /// Name length.
    pub name_len: u8,
    /// Items in this group.
    pub items: [ConfigItem; MAX_ITEMS_PER_GROUP],
    /// Number of active items.
    pub item_count: usize,
    /// Child sub-groups.
    pub children: [Option<ConfigGroupChild>; MAX_CHILDREN_PER_GROUP],
    /// Number of active children.
    pub child_count: usize,
    /// Default attribute names applied to newly created items.
    pub default_attrs: [Option<DefaultAttr>; MAX_DEFAULT_ATTRS],
    /// Number of default attributes.
    pub default_attr_count: usize,
    /// Whether this group is active.
    pub active: bool,
}

/// A child sub-group reference (stored inline to avoid heap allocation).
#[derive(Debug, Clone)]
pub struct ConfigGroupChild {
    /// Child group name.
    pub name: [u8; MAX_NAME_LEN],
    /// Name length.
    pub name_len: u8,
    /// Items in this child group.
    pub items: [ConfigItem; MAX_ITEMS_PER_GROUP],
    /// Number of active items.
    pub item_count: usize,
    /// Whether this child is active.
    pub active: bool,
}

impl ConfigGroupChild {
    /// Create a new empty child group.
    fn new(name: &str) -> Result<Self> {
        const EMPTY_ITEM: ConfigItem = ConfigItem::empty();
        let name_bytes = name.as_bytes();
        if name_bytes.is_empty() || name_bytes.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut child = Self {
            name: [0; MAX_NAME_LEN],
            name_len: name_bytes.len() as u8,
            items: [EMPTY_ITEM; MAX_ITEMS_PER_GROUP],
            item_count: 0,
            active: true,
        };
        child.name[..name_bytes.len()].copy_from_slice(name_bytes);
        Ok(child)
    }

    /// Return the child group name as bytes.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

/// A default attribute definition for a group.
#[derive(Debug, Clone)]
pub struct DefaultAttr {
    /// Attribute name.
    pub name: [u8; ATTR_NAME_LEN],
    /// Name length.
    pub name_len: u8,
    /// Whether the attribute is writable.
    pub writable: bool,
}

impl DefaultAttr {
    /// Create a new default attribute.
    fn new(name: &str, writable: bool) -> Result<Self> {
        let name_bytes = name.as_bytes();
        if name_bytes.is_empty() || name_bytes.len() > ATTR_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut attr = Self {
            name: [0; ATTR_NAME_LEN],
            name_len: name_bytes.len() as u8,
            writable,
        };
        attr.name[..name_bytes.len()].copy_from_slice(name_bytes);
        Ok(attr)
    }
}

impl ConfigGroup {
    /// Create an empty (inactive) group.
    const fn empty() -> Self {
        const EMPTY_ITEM: ConfigItem = ConfigItem::empty();
        const NONE_CHILD: Option<ConfigGroupChild> = None;
        const NONE_ATTR: Option<DefaultAttr> = None;
        Self {
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            items: [EMPTY_ITEM; MAX_ITEMS_PER_GROUP],
            item_count: 0,
            children: [NONE_CHILD; MAX_CHILDREN_PER_GROUP],
            child_count: 0,
            default_attrs: [NONE_ATTR; MAX_DEFAULT_ATTRS],
            default_attr_count: 0,
            active: false,
        }
    }

    /// Create a new group with the given name.
    fn new(name: &str) -> Result<Self> {
        let name_bytes = name.as_bytes();
        if name_bytes.is_empty() || name_bytes.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut group = Self::empty();
        group.name[..name_bytes.len()].copy_from_slice(name_bytes);
        group.name_len = name_bytes.len() as u8;
        group.active = true;
        Ok(group)
    }

    /// Add a default attribute that will be applied to new items.
    pub fn add_default_attr(&mut self, name: &str, writable: bool) -> Result<()> {
        if self.default_attr_count >= MAX_DEFAULT_ATTRS {
            return Err(Error::OutOfMemory);
        }
        let attr = DefaultAttr::new(name, writable)?;
        for slot in self.default_attrs.iter_mut() {
            if slot.is_none() {
                *slot = Some(attr);
                self.default_attr_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Create a new item within this group, applying default attrs.
    pub fn make_item(&mut self, name: &str) -> Result<usize> {
        if self.item_count >= MAX_ITEMS_PER_GROUP {
            return Err(Error::OutOfMemory);
        }
        let name_bytes = name.as_bytes();

        // Check for duplicate names.
        for item in &self.items {
            if item.active && item.name_bytes() == name_bytes {
                return Err(Error::AlreadyExists);
            }
        }

        let mut item = ConfigItem::new(name)?;

        // Apply default attributes.
        for default in self.default_attrs.iter().flatten() {
            let attr_name = core::str::from_utf8(&default.name[..default.name_len as usize])
                .map_err(|_| Error::InvalidArgument)?;
            // Ignore errors from adding defaults (best effort).
            let _ = item.add_attr(attr_name, default.writable);
        }

        for (idx, slot) in self.items.iter_mut().enumerate() {
            if !slot.active {
                *slot = item;
                self.item_count += 1;
                return Ok(idx);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove an item from this group by name.
    pub fn remove_item(&mut self, name: &str) -> Result<()> {
        let name_bytes = name.as_bytes();
        for item in self.items.iter_mut() {
            if item.active && item.name_bytes() == name_bytes {
                item.active = false;
                self.item_count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Add a child sub-group.
    pub fn add_child(&mut self, name: &str) -> Result<usize> {
        if self.child_count >= MAX_CHILDREN_PER_GROUP {
            return Err(Error::OutOfMemory);
        }
        let name_bytes = name.as_bytes();
        for child in self.children.iter().flatten() {
            if child.active && child.name_bytes() == name_bytes {
                return Err(Error::AlreadyExists);
            }
        }
        let child = ConfigGroupChild::new(name)?;
        for (idx, slot) in self.children.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(child);
                self.child_count += 1;
                return Ok(idx);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a child sub-group by name.
    pub fn remove_child(&mut self, name: &str) -> Result<()> {
        let name_bytes = name.as_bytes();
        for slot in self.children.iter_mut() {
            if let Some(child) = slot {
                if child.active && child.name_bytes() == name_bytes {
                    if child.item_count > 0 {
                        return Err(Error::Busy);
                    }
                    *slot = None;
                    self.child_count -= 1;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Return the group name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

// ── ConfigSubsystem ─────────────────────────────────────────────

/// A configfs subsystem — the top-level container.
///
/// Subsystems register with configfs and provide a root group
/// under which user space can create configuration items.
#[derive(Debug, Clone)]
pub struct ConfigSubsystem {
    /// Subsystem name.
    pub name: [u8; MAX_NAME_LEN],
    /// Name length.
    pub name_len: u8,
    /// Root group for this subsystem.
    pub root_group: ConfigGroup,
    /// Owner module identifier.
    pub owner_id: u32,
    /// Whether this subsystem is active.
    pub active: bool,
}

impl ConfigSubsystem {
    /// Create an empty (inactive) subsystem.
    const fn empty() -> Self {
        Self {
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            root_group: ConfigGroup::empty(),
            owner_id: 0,
            active: false,
        }
    }

    /// Create a new subsystem with the given name and owner.
    fn new(name: &str, owner_id: u32) -> Result<Self> {
        let name_bytes = name.as_bytes();
        if name_bytes.is_empty() || name_bytes.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let root_group = ConfigGroup::new(name)?;
        let mut sub = Self {
            name: [0; MAX_NAME_LEN],
            name_len: name_bytes.len() as u8,
            root_group,
            owner_id,
            active: true,
        };
        sub.name[..name_bytes.len()].copy_from_slice(name_bytes);
        Ok(sub)
    }

    /// Return the subsystem name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

// ── ConfigFs ────────────────────────────────────────────────────

/// ConfigFS filesystem instance.
///
/// Manages up to [`MAX_SUBSYSTEMS`] subsystems. Each subsystem
/// has a root group under which items and sub-groups can be
/// created/destroyed via `mkdir`/`rmdir`.
pub struct ConfigFs {
    /// Registered subsystems.
    subsystems: [ConfigSubsystem; MAX_SUBSYSTEMS],
    /// Number of active subsystems.
    subsystem_count: usize,
    /// Whether the filesystem is mounted.
    mounted: bool,
}

impl ConfigFs {
    /// Create a new configfs instance.
    pub const fn new() -> Self {
        const EMPTY_SUB: ConfigSubsystem = ConfigSubsystem::empty();
        Self {
            subsystems: [EMPTY_SUB; MAX_SUBSYSTEMS],
            subsystem_count: 0,
            mounted: false,
        }
    }

    /// Mount the configfs filesystem.
    pub fn mount(&mut self) -> Result<()> {
        if self.mounted {
            return Err(Error::Busy);
        }
        self.mounted = true;
        Ok(())
    }

    /// Unmount the configfs filesystem.
    pub fn unmount(&mut self) -> Result<()> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        self.mounted = false;
        Ok(())
    }

    /// Register a new subsystem.
    pub fn register_subsystem(&mut self, name: &str, owner_id: u32) -> Result<usize> {
        if self.subsystem_count >= MAX_SUBSYSTEMS {
            return Err(Error::OutOfMemory);
        }
        let name_bytes = name.as_bytes();

        // Check for duplicates.
        for sub in &self.subsystems {
            if sub.active && sub.name_bytes() == name_bytes {
                return Err(Error::AlreadyExists);
            }
        }

        let subsystem = ConfigSubsystem::new(name, owner_id)?;
        for (idx, slot) in self.subsystems.iter_mut().enumerate() {
            if !slot.active {
                *slot = subsystem;
                self.subsystem_count += 1;
                return Ok(idx);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregister a subsystem by name.
    pub fn unregister_subsystem(&mut self, name: &str) -> Result<()> {
        let name_bytes = name.as_bytes();
        for sub in self.subsystems.iter_mut() {
            if sub.active && sub.name_bytes() == name_bytes {
                sub.active = false;
                self.subsystem_count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Find a subsystem by name, returning its index.
    fn find_subsystem(&self, name: &str) -> Option<usize> {
        let name_bytes = name.as_bytes();
        self.subsystems
            .iter()
            .position(|s| s.active && s.name_bytes() == name_bytes)
    }

    /// Create a directory (item) under a subsystem's root group.
    ///
    /// Path format: `subsystem_name/item_name`
    pub fn mkdir(&mut self, subsystem: &str, item_name: &str) -> Result<usize> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        let idx = self.find_subsystem(subsystem).ok_or(Error::NotFound)?;
        self.subsystems[idx].root_group.make_item(item_name)
    }

    /// Remove a directory (item) from a subsystem's root group.
    pub fn rmdir(&mut self, subsystem: &str, item_name: &str) -> Result<()> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        let idx = self.find_subsystem(subsystem).ok_or(Error::NotFound)?;
        self.subsystems[idx].root_group.remove_item(item_name)
    }

    /// Write to an attribute within a subsystem item.
    pub fn write_attr(
        &mut self,
        subsystem: &str,
        item_name: &str,
        attr_name: &str,
        data: &[u8],
    ) -> Result<usize> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        let sub_idx = self.find_subsystem(subsystem).ok_or(Error::NotFound)?;
        let item_name_bytes = item_name.as_bytes();
        let group = &mut self.subsystems[sub_idx].root_group;

        for item in group.items.iter_mut() {
            if item.active && item.name_bytes() == item_name_bytes {
                let attr_idx = item.find_attr(attr_name).ok_or(Error::NotFound)?;
                return item.attrs[attr_idx].store(data);
            }
        }
        Err(Error::NotFound)
    }

    /// Read an attribute value from a subsystem item.
    pub fn read_attr(
        &self,
        subsystem: &str,
        item_name: &str,
        attr_name: &str,
        buf: &mut [u8],
    ) -> Result<usize> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        let sub_idx = self.find_subsystem(subsystem).ok_or(Error::NotFound)?;
        let item_name_bytes = item_name.as_bytes();
        let group = &self.subsystems[sub_idx].root_group;

        for item in &group.items {
            if item.active && item.name_bytes() == item_name_bytes {
                let attr_idx = item.find_attr(attr_name).ok_or(Error::NotFound)?;
                return item.attrs[attr_idx].show(buf);
            }
        }
        Err(Error::NotFound)
    }

    /// List items in a subsystem's root group.
    ///
    /// Returns the number of active items found, writing their names
    /// into `names` (up to `names.len()` entries). Each name is
    /// written as `[u8; MAX_NAME_LEN]`.
    pub fn list(
        &self,
        subsystem: &str,
        names: &mut [[u8; MAX_NAME_LEN]],
        name_lens: &mut [u8],
    ) -> Result<usize> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        let sub_idx = self.find_subsystem(subsystem).ok_or(Error::NotFound)?;
        let group = &self.subsystems[sub_idx].root_group;

        let mut count = 0;
        for item in &group.items {
            if item.active && count < names.len() {
                names[count] = item.name;
                name_lens[count] = item.name_len;
                count += 1;
            }
        }
        Ok(count)
    }

    /// Return the number of registered subsystems.
    pub fn subsystem_count(&self) -> usize {
        self.subsystem_count
    }
}

impl Default for ConfigFs {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for ConfigFs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConfigFs")
            .field("mounted", &self.mounted)
            .field("subsystem_count", &self.subsystem_count)
            .finish()
    }
}

// ── ConfigRegistry ──────────────────────────────────────────────

/// Global registry for configfs subsystems.
///
/// Kernel modules register their subsystems here so that configfs
/// can present them under the mount point.
pub struct ConfigRegistry {
    /// Registered subsystem names.
    names: [[u8; MAX_NAME_LEN]; MAX_REGISTRY_ENTRIES],
    /// Name lengths.
    name_lens: [u8; MAX_REGISTRY_ENTRIES],
    /// Owner IDs.
    owner_ids: [u32; MAX_REGISTRY_ENTRIES],
    /// Whether each slot is active.
    active: [bool; MAX_REGISTRY_ENTRIES],
}

impl ConfigRegistry {
    /// Create a new empty registry.
    pub const fn new() -> Self {
        Self {
            names: [[0u8; MAX_NAME_LEN]; MAX_REGISTRY_ENTRIES],
            name_lens: [0; MAX_REGISTRY_ENTRIES],
            owner_ids: [0; MAX_REGISTRY_ENTRIES],
            active: [false; MAX_REGISTRY_ENTRIES],
        }
    }

    /// Register a subsystem.
    pub fn register(&mut self, name: &str, owner_id: u32) -> Result<usize> {
        let name_bytes = name.as_bytes();
        if name_bytes.is_empty() || name_bytes.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }

        // Check for duplicates.
        for (idx, used) in self.active.iter().enumerate() {
            if *used
                && self.name_lens[idx] as usize == name_bytes.len()
                && &self.names[idx][..self.name_lens[idx] as usize] == name_bytes
            {
                return Err(Error::AlreadyExists);
            }
        }

        for (idx, used) in self.active.iter_mut().enumerate() {
            if !*used {
                self.names[idx][..name_bytes.len()].copy_from_slice(name_bytes);
                self.name_lens[idx] = name_bytes.len() as u8;
                self.owner_ids[idx] = owner_id;
                *used = true;
                return Ok(idx);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregister a subsystem by name.
    pub fn unregister(&mut self, name: &str) -> Result<()> {
        let name_bytes = name.as_bytes();
        for (idx, used) in self.active.iter_mut().enumerate() {
            if *used
                && self.name_lens[idx] as usize == name_bytes.len()
                && &self.names[idx][..self.name_lens[idx] as usize] == name_bytes
            {
                *used = false;
                self.name_lens[idx] = 0;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Find a registered subsystem by name.
    pub fn find(&self, name: &str) -> Option<usize> {
        let name_bytes = name.as_bytes();
        for (idx, used) in self.active.iter().enumerate() {
            if *used
                && self.name_lens[idx] as usize == name_bytes.len()
                && &self.names[idx][..self.name_lens[idx] as usize] == name_bytes
            {
                return Some(idx);
            }
        }
        None
    }

    /// Return the number of active registrations.
    pub fn active_count(&self) -> usize {
        self.active.iter().filter(|a| **a).count()
    }
}

impl Default for ConfigRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for ConfigRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConfigRegistry")
            .field("active_entries", &self.active_count())
            .finish()
    }
}
