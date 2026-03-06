// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! sysfs attribute groups.
//!
//! Attribute groups allow a kernel object to expose a named subdirectory of
//! related sysfs attributes. Each group has a name (subdirectory), a list of
//! regular attributes, and optional binary attributes.
//!
//! # Operations
//!
//! - [`sysfs_create_group`] — create a group and all its attributes
//! - [`sysfs_remove_group`] — remove a group and its attributes
//! - [`sysfs_update_group`] — refresh visibility of group attributes
//! - [`sysfs_create_bin_group`] — create a group with binary attributes
//!
//! # References
//!
//! - Linux `fs/sysfs/group.c`
//! - `include/linux/sysfs.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum attributes per group.
pub const MAX_ATTRS_PER_GROUP: usize = 64;

/// Maximum attribute name length.
pub const MAX_ATTR_NAME: usize = 128;

/// Maximum group name length.
pub const MAX_GROUP_NAME: usize = 64;

/// Maximum groups per kobject.
pub const MAX_GROUPS: usize = 32;

/// Maximum binary attribute data size.
pub const MAX_BIN_ATTR_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single sysfs attribute (file) within a group.
#[derive(Clone)]
pub struct SysfsAttr {
    /// Attribute name.
    pub name: [u8; MAX_ATTR_NAME],
    /// Name length.
    pub name_len: usize,
    /// File mode (e.g. `0o644`).
    pub mode: u32,
    /// Whether this attribute is visible (controlled by group visibility).
    pub visible: bool,
    /// Attribute slot in use.
    pub in_use: bool,
}

impl SysfsAttr {
    fn empty() -> Self {
        Self {
            name: [0u8; MAX_ATTR_NAME],
            name_len: 0,
            mode: 0o444,
            visible: true,
            in_use: false,
        }
    }

    fn new(name: &[u8], mode: u32) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_ATTR_NAME {
            return Err(Error::InvalidArgument);
        }
        let mut attr = Self::empty();
        attr.name[..name.len()].copy_from_slice(name);
        attr.name_len = name.len();
        attr.mode = mode;
        attr.visible = true;
        attr.in_use = true;
        Ok(attr)
    }

    /// Return the attribute name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// A binary sysfs attribute (large data blob).
#[derive(Clone)]
pub struct SysfsBinAttr {
    /// Attribute name.
    pub name: [u8; MAX_ATTR_NAME],
    /// Name length.
    pub name_len: usize,
    /// Mode bits.
    pub mode: u32,
    /// Maximum size of binary data.
    pub size: usize,
    /// In use.
    pub in_use: bool,
}

impl SysfsBinAttr {
    fn empty() -> Self {
        Self {
            name: [0u8; MAX_ATTR_NAME],
            name_len: 0,
            mode: 0o444,
            size: 0,
            in_use: false,
        }
    }

    fn new(name: &[u8], mode: u32, size: usize) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_ATTR_NAME {
            return Err(Error::InvalidArgument);
        }
        let mut attr = Self::empty();
        attr.name[..name.len()].copy_from_slice(name);
        attr.name_len = name.len();
        attr.mode = mode;
        attr.size = size;
        attr.in_use = true;
        Ok(attr)
    }

    /// Return the attribute name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// An attribute group (subdirectory of sysfs).
pub struct AttributeGroup {
    /// Group name (empty string means place attrs in parent dir).
    pub name: [u8; MAX_GROUP_NAME],
    /// Name length.
    pub name_len: usize,
    /// Regular attributes.
    pub attrs: [SysfsAttr; MAX_ATTRS_PER_GROUP],
    /// Number of regular attributes.
    pub attr_count: usize,
    /// Binary attributes.
    pub bin_attrs: [SysfsBinAttr; MAX_ATTRS_PER_GROUP],
    /// Number of binary attributes.
    pub bin_attr_count: usize,
    /// Group is registered.
    pub registered: bool,
}

impl AttributeGroup {
    /// Create an empty group with the given name.
    pub fn new(name: &[u8]) -> Result<Self> {
        if name.len() > MAX_GROUP_NAME {
            return Err(Error::InvalidArgument);
        }
        let mut group = Self {
            name: [0u8; MAX_GROUP_NAME],
            name_len: name.len(),
            attrs: core::array::from_fn(|_| SysfsAttr::empty()),
            attr_count: 0,
            bin_attrs: core::array::from_fn(|_| SysfsBinAttr::empty()),
            bin_attr_count: 0,
            registered: false,
        };
        group.name[..name.len()].copy_from_slice(name);
        Ok(group)
    }

    /// Return the group name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Add a regular attribute to the group.
    pub fn add_attr(&mut self, name: &[u8], mode: u32) -> Result<()> {
        if self.attr_count >= MAX_ATTRS_PER_GROUP {
            return Err(Error::OutOfMemory);
        }
        let attr = SysfsAttr::new(name, mode)?;
        self.attrs[self.attr_count] = attr;
        self.attr_count += 1;
        Ok(())
    }

    /// Add a binary attribute to the group.
    pub fn add_bin_attr(&mut self, name: &[u8], mode: u32, size: usize) -> Result<()> {
        if self.bin_attr_count >= MAX_ATTRS_PER_GROUP {
            return Err(Error::OutOfMemory);
        }
        let attr = SysfsBinAttr::new(name, mode, size)?;
        self.bin_attrs[self.bin_attr_count] = attr;
        self.bin_attr_count += 1;
        Ok(())
    }
}

/// Registry of all attribute groups for a kobject.
pub struct GroupRegistry {
    groups: [Option<AttributeGroup>; MAX_GROUPS],
    count: usize,
}

impl GroupRegistry {
    /// Create an empty group registry.
    pub fn new() -> Self {
        Self {
            groups: core::array::from_fn(|_| None),
            count: 0,
        }
    }

    fn find(&self, name: &[u8]) -> Option<usize> {
        for i in 0..MAX_GROUPS {
            if let Some(ref g) = self.groups[i] {
                if g.name_bytes() == name {
                    return Some(i);
                }
            }
        }
        None
    }

    fn free_slot(&self) -> Option<usize> {
        for i in 0..MAX_GROUPS {
            if self.groups[i].is_none() {
                return Some(i);
            }
        }
        None
    }
}

impl Default for GroupRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Create a sysfs attribute group and register it.
///
/// Returns `Err(AlreadyExists)` if a group with the same name is already
/// registered.
pub fn sysfs_create_group(registry: &mut GroupRegistry, group: AttributeGroup) -> Result<()> {
    if registry.find(group.name_bytes()).is_some() {
        return Err(Error::AlreadyExists);
    }
    let slot = registry.free_slot().ok_or(Error::OutOfMemory)?;
    let mut g = group;
    g.registered = true;
    registry.groups[slot] = Some(g);
    registry.count += 1;
    Ok(())
}

/// Remove a sysfs attribute group by name.
pub fn sysfs_remove_group(registry: &mut GroupRegistry, name: &[u8]) -> Result<()> {
    let slot = registry.find(name).ok_or(Error::NotFound)?;
    registry.groups[slot] = None;
    registry.count = registry.count.saturating_sub(1);
    Ok(())
}

/// Update the visibility of attributes in a group.
///
/// `visible_fn` is called with each attribute name; returning `false` hides
/// the attribute.
pub fn sysfs_update_group<F>(registry: &mut GroupRegistry, name: &[u8], visible_fn: F) -> Result<()>
where
    F: Fn(&[u8]) -> bool,
{
    let slot = registry.find(name).ok_or(Error::NotFound)?;
    if let Some(ref mut g) = registry.groups[slot] {
        for i in 0..g.attr_count {
            let attr_name_bytes = &g.attrs[i].name[..g.attrs[i].name_len];
            // We copy the name to avoid borrow issues.
            let mut name_copy = [0u8; MAX_ATTR_NAME];
            let nl = g.attrs[i].name_len;
            name_copy[..nl].copy_from_slice(attr_name_bytes);
            let visible = visible_fn(&name_copy[..nl]);
            g.attrs[i].visible = visible;
        }
    }
    Ok(())
}

/// Create a group that contains only binary attributes.
pub fn sysfs_create_bin_group(
    registry: &mut GroupRegistry,
    name: &[u8],
    bin_attrs: &[(&[u8], u32, usize)], // (name, mode, size)
) -> Result<()> {
    let mut group = AttributeGroup::new(name)?;
    for &(aname, mode, size) in bin_attrs {
        group.add_bin_attr(aname, mode, size)?;
    }
    sysfs_create_group(registry, group)
}

/// Look up a group by name.
pub fn sysfs_find_group<'a>(
    registry: &'a GroupRegistry,
    name: &[u8],
) -> Option<&'a AttributeGroup> {
    let slot = registry.find(name)?;
    registry.groups[slot].as_ref()
}

/// List all group names into `out`. Returns count written.
pub fn sysfs_list_groups(
    registry: &GroupRegistry,
    out: &mut [([u8; MAX_GROUP_NAME], usize)],
) -> usize {
    let mut written = 0;
    for i in 0..MAX_GROUPS {
        if written >= out.len() {
            break;
        }
        if let Some(ref g) = registry.groups[i] {
            out[written] = (g.name, g.name_len);
            written += 1;
        }
    }
    written
}

/// Return number of registered groups.
pub fn group_count(registry: &GroupRegistry) -> usize {
    registry.count
}
