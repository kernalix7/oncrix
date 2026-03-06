// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! configfs subsystem — configurable filesystem objects.
//!
//! configfs is a RAM-based filesystem where kernel objects can be configured
//! by userspace by creating and removing directories and writing to attribute
//! files. Userspace "commits" a configuration by writing to a special
//! attribute, triggering kernel-side validation and activation.
//!
//! # Design
//!
//! - [`ConfigItem`] — a leaf object (no children)
//! - [`ConfigGroup`] — a group that can contain child items or groups
//! - [`ConfigSubsystem`] — root of a configfs subsystem
//! - `make_item` / `drop_item` — lifecycle callbacks
//! - `attribute_show` / `attribute_store` — per-attribute I/O
//!
//! # References
//!
//! - Linux `fs/configfs/`
//! - `include/linux/configfs.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum children per group.
pub const MAX_CHILDREN: usize = 64;

/// Maximum attributes per item/group.
pub const MAX_ITEM_ATTRS: usize = 32;

/// Maximum name length.
pub const MAX_NAME: usize = 128;

/// Maximum attribute value size.
pub const MAX_ATTR_VALUE: usize = 4096;

/// Maximum subsystems.
pub const MAX_SUBSYSTEMS: usize = 16;

/// Maximum total items across all groups.
pub const MAX_TOTAL_ITEMS: usize = 256;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// State of a configfs item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemState {
    /// Item exists but is not yet committed.
    Uncommitted,
    /// Item has been committed and is active.
    Committed,
    /// Item is being dropped.
    Dropping,
}

/// A single configfs attribute.
#[derive(Clone)]
pub struct ConfigAttr {
    /// Attribute name.
    pub name: [u8; MAX_NAME],
    /// Name length.
    pub name_len: usize,
    /// File mode (0o644 for read-write).
    pub mode: u32,
    /// Current value (raw bytes).
    pub value: [u8; MAX_ATTR_VALUE],
    /// Value length.
    pub value_len: usize,
    /// In use.
    pub in_use: bool,
}

impl ConfigAttr {
    fn empty() -> Self {
        Self {
            name: [0u8; MAX_NAME],
            name_len: 0,
            mode: 0o644,
            value: [0u8; MAX_ATTR_VALUE],
            value_len: 0,
            in_use: false,
        }
    }

    fn new(name: &[u8], mode: u32) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_NAME {
            return Err(Error::InvalidArgument);
        }
        let mut attr = Self::empty();
        attr.name[..name.len()].copy_from_slice(name);
        attr.name_len = name.len();
        attr.mode = mode;
        attr.in_use = true;
        Ok(attr)
    }

    /// Return attribute name bytes.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return attribute value bytes.
    pub fn value_bytes(&self) -> &[u8] {
        &self.value[..self.value_len]
    }
}

/// A configfs item (leaf node).
#[derive(Clone)]
pub struct ConfigItem {
    /// Item name.
    pub name: [u8; MAX_NAME],
    /// Name length.
    pub name_len: usize,
    /// Item ID (opaque).
    pub id: u64,
    /// Parent group ID.
    pub parent_id: u64,
    /// Current state.
    pub state: ItemState,
    /// Attributes.
    pub attrs: [ConfigAttr; MAX_ITEM_ATTRS],
    /// Number of attributes.
    pub attr_count: usize,
    /// In use.
    pub in_use: bool,
    /// Is a group (has children).
    pub is_group: bool,
    /// Children IDs (only valid if is_group).
    pub children: [u64; MAX_CHILDREN],
    /// Number of children.
    pub child_count: usize,
}

impl ConfigItem {
    fn empty() -> Self {
        Self {
            name: [0u8; MAX_NAME],
            name_len: 0,
            id: 0,
            parent_id: 0,
            state: ItemState::Uncommitted,
            attrs: core::array::from_fn(|_| ConfigAttr::empty()),
            attr_count: 0,
            in_use: false,
            is_group: false,
            children: [0u64; MAX_CHILDREN],
            child_count: 0,
        }
    }

    /// Return item name bytes.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// A configfs subsystem (root group with subsystem-level registration).
pub struct ConfigSubsystem {
    /// Subsystem name.
    pub name: [u8; MAX_NAME],
    /// Name length.
    pub name_len: usize,
    /// Root item ID.
    pub root_id: u64,
    /// Registered.
    pub registered: bool,
}

impl ConfigSubsystem {
    /// Create a new subsystem with the given name.
    pub fn new(name: &[u8]) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_NAME {
            return Err(Error::InvalidArgument);
        }
        let mut ss = Self {
            name: [0u8; MAX_NAME],
            name_len: name.len(),
            root_id: 0,
            registered: false,
        };
        ss.name[..name.len()].copy_from_slice(name);
        Ok(ss)
    }

    /// Return subsystem name bytes.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// Global configfs state.
pub struct ConfigfsState {
    items: [ConfigItem; MAX_TOTAL_ITEMS],
    item_count: usize,
    subsystems: [Option<ConfigSubsystem>; MAX_SUBSYSTEMS],
    subsystem_count: usize,
    next_id: u64,
}

impl ConfigfsState {
    /// Create a new empty configfs state.
    pub fn new() -> Self {
        Self {
            items: core::array::from_fn(|_| ConfigItem::empty()),
            item_count: 0,
            subsystems: core::array::from_fn(|_| None),
            subsystem_count: 0,
            next_id: 1,
        }
    }

    fn find_item(&self, id: u64) -> Option<usize> {
        for i in 0..MAX_TOTAL_ITEMS {
            if self.items[i].in_use && self.items[i].id == id {
                return Some(i);
            }
        }
        None
    }

    fn find_item_by_name(&self, parent_id: u64, name: &[u8]) -> Option<usize> {
        for i in 0..MAX_TOTAL_ITEMS {
            if self.items[i].in_use
                && self.items[i].parent_id == parent_id
                && self.items[i].name_bytes() == name
            {
                return Some(i);
            }
        }
        None
    }

    fn free_item_slot(&self) -> Option<usize> {
        for i in 0..MAX_TOTAL_ITEMS {
            if !self.items[i].in_use {
                return Some(i);
            }
        }
        None
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

impl Default for ConfigfsState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Create a new configfs item under `parent_id`.
///
/// Returns the new item ID.
pub fn make_item(
    state: &mut ConfigfsState,
    parent_id: u64,
    name: &[u8],
    is_group: bool,
) -> Result<u64> {
    if name.is_empty() || name.len() > MAX_NAME {
        return Err(Error::InvalidArgument);
    }
    if state.find_item_by_name(parent_id, name).is_some() {
        return Err(Error::AlreadyExists);
    }
    // Verify parent exists (unless it's the root, id 0).
    if parent_id != 0 && state.find_item(parent_id).is_none() {
        return Err(Error::NotFound);
    }

    let slot = state.free_item_slot().ok_or(Error::OutOfMemory)?;
    let id = state.alloc_id();
    let mut item = ConfigItem::empty();
    item.name[..name.len()].copy_from_slice(name);
    item.name_len = name.len();
    item.id = id;
    item.parent_id = parent_id;
    item.is_group = is_group;
    item.in_use = true;

    // Register as child of parent.
    if parent_id != 0 {
        if let Some(pidx) = state.find_item(parent_id) {
            if state.items[pidx].child_count < MAX_CHILDREN {
                let cc = state.items[pidx].child_count;
                state.items[pidx].children[cc] = id;
                state.items[pidx].child_count += 1;
            }
        }
    }

    state.items[slot] = item;
    state.item_count += 1;
    Ok(id)
}

/// Drop (remove) a configfs item by ID.
///
/// Returns `Err(Busy)` if the item still has children.
pub fn drop_item(state: &mut ConfigfsState, id: u64) -> Result<()> {
    let slot = state.find_item(id).ok_or(Error::NotFound)?;
    if state.items[slot].child_count > 0 {
        return Err(Error::Busy);
    }
    // Remove from parent's children list.
    let parent_id = state.items[slot].parent_id;
    if parent_id != 0 {
        if let Some(pidx) = state.find_item(parent_id) {
            let cc = state.items[pidx].child_count;
            let mut new_cc = 0;
            let mut new_children = [0u64; MAX_CHILDREN];
            for j in 0..cc {
                if state.items[pidx].children[j] != id {
                    new_children[new_cc] = state.items[pidx].children[j];
                    new_cc += 1;
                }
            }
            state.items[pidx].children = new_children;
            state.items[pidx].child_count = new_cc;
        }
    }
    state.items[slot] = ConfigItem::empty();
    state.item_count = state.item_count.saturating_sub(1);
    Ok(())
}

/// Show (read) an attribute value for item `id`.
///
/// Writes the value into `out`. Returns bytes written.
pub fn attribute_show(
    state: &ConfigfsState,
    id: u64,
    attr_name: &[u8],
    out: &mut [u8],
) -> Result<usize> {
    let slot = state.find_item(id).ok_or(Error::NotFound)?;
    for i in 0..state.items[slot].attr_count {
        if state.items[slot].attrs[i].in_use && state.items[slot].attrs[i].name_bytes() == attr_name
        {
            let vlen = state.items[slot].attrs[i].value_len;
            let copy = vlen.min(out.len());
            out[..copy].copy_from_slice(&state.items[slot].attrs[i].value[..copy]);
            return Ok(copy);
        }
    }
    Err(Error::NotFound)
}

/// Store (write) an attribute value for item `id`.
pub fn attribute_store(
    state: &mut ConfigfsState,
    id: u64,
    attr_name: &[u8],
    val: &[u8],
) -> Result<()> {
    if val.len() > MAX_ATTR_VALUE {
        return Err(Error::InvalidArgument);
    }
    let slot = state.find_item(id).ok_or(Error::NotFound)?;

    // Find existing attribute.
    for i in 0..state.items[slot].attr_count {
        if state.items[slot].attrs[i].in_use && state.items[slot].attrs[i].name_bytes() == attr_name
        {
            state.items[slot].attrs[i].value[..val.len()].copy_from_slice(val);
            state.items[slot].attrs[i].value_len = val.len();
            return Ok(());
        }
    }

    // Create new attribute.
    if state.items[slot].attr_count >= MAX_ITEM_ATTRS {
        return Err(Error::OutOfMemory);
    }
    let new_attr = ConfigAttr::new(attr_name, 0o644)?;
    let ac = state.items[slot].attr_count;
    state.items[slot].attrs[ac] = new_attr;
    state.items[slot].attrs[ac].value[..val.len()].copy_from_slice(val);
    state.items[slot].attrs[ac].value_len = val.len();
    state.items[slot].attr_count += 1;
    Ok(())
}

/// Commit an item — transition from `Uncommitted` to `Committed`.
pub fn commit_item(state: &mut ConfigfsState, id: u64) -> Result<()> {
    let slot = state.find_item(id).ok_or(Error::NotFound)?;
    if state.items[slot].state != ItemState::Uncommitted {
        return Err(Error::InvalidArgument);
    }
    state.items[slot].state = ItemState::Committed;
    Ok(())
}

/// Uncommit an item — transition from `Committed` back to `Uncommitted`.
pub fn uncommit_item(state: &mut ConfigfsState, id: u64) -> Result<()> {
    let slot = state.find_item(id).ok_or(Error::NotFound)?;
    if state.items[slot].state != ItemState::Committed {
        return Err(Error::InvalidArgument);
    }
    state.items[slot].state = ItemState::Uncommitted;
    Ok(())
}

/// Register a subsystem into configfs.
pub fn register_subsystem(state: &mut ConfigfsState, subsystem: ConfigSubsystem) -> Result<u64> {
    for i in 0..MAX_SUBSYSTEMS {
        if let Some(ref ss) = state.subsystems[i] {
            if ss.name_bytes() == subsystem.name_bytes() {
                return Err(Error::AlreadyExists);
            }
        }
    }
    // Find free slot.
    let slot = state
        .subsystems
        .iter()
        .position(|s| s.is_none())
        .ok_or(Error::OutOfMemory)?;

    // Create root group for subsystem.
    let root_id = make_item(state, 0, subsystem.name_bytes(), true)?;
    let mut ss = subsystem;
    ss.root_id = root_id;
    ss.registered = true;
    state.subsystems[slot] = Some(ss);
    state.subsystem_count += 1;
    Ok(root_id)
}

/// Unregister a subsystem by name.
pub fn unregister_subsystem(state: &mut ConfigfsState, name: &[u8]) -> Result<()> {
    for i in 0..MAX_SUBSYSTEMS {
        let matches = state.subsystems[i]
            .as_ref()
            .map_or(false, |ss| ss.name_bytes() == name);
        if matches {
            let root_id = state.subsystems[i].as_ref().unwrap().root_id;
            drop_item(state, root_id)?;
            state.subsystems[i] = None;
            state.subsystem_count = state.subsystem_count.saturating_sub(1);
            return Ok(());
        }
    }
    Err(Error::NotFound)
}

/// Look up an item by ID.
pub fn find_item(state: &ConfigfsState, id: u64) -> Option<&ConfigItem> {
    let slot = state.find_item(id)?;
    Some(&state.items[slot])
}
