// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Sysfs kobject representation and hierarchy.
//!
//! Every kernel object (device, bus, driver, class) exposed in sysfs is
//! represented by a `Kobject`.  This module implements the kobject reference
//! lifecycle, the parent/child relationship used to build the sysfs directory
//! tree, and the attribute operations that expose kobject state as files.

use oncrix_lib::{Error, Result};

/// Maximum length of a kobject name.
pub const KOBJECT_NAME_MAX: usize = 64;

/// Maximum number of kobjects in the global registry.
pub const KOBJECT_MAX: usize = 4096;

/// Maximum number of child kobjects per parent.
pub const KOBJECT_MAX_CHILDREN: usize = 128;

/// Unique kobject identifier (kernel-assigned).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KobjectId(pub u32);

impl KobjectId {
    /// The root kobject (no parent).
    pub const ROOT: Self = Self(0);
}

/// Kobject state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KobjectState {
    /// Kobject has been created but not yet registered in sysfs.
    Initialized,
    /// Kobject is active in sysfs.
    Active,
    /// Kobject is being removed from sysfs.
    Removing,
    /// Kobject has been removed; its ID may be reused.
    Removed,
}

/// A single kobject attribute (exposes one read/write file under sysfs).
#[derive(Debug, Clone)]
pub struct KobjectAttr {
    /// Attribute filename (e.g., "uevent", "power/runtime_status").
    pub name: [u8; 64],
    pub name_len: u8,
    /// POSIX permission bits.
    pub mode: u16,
    /// Cached value (up to 256 bytes; real kernel does dynamic allocation).
    pub value: [u8; 256],
    pub value_len: u16,
}

impl KobjectAttr {
    /// Name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Value as a byte slice.
    pub fn value_bytes(&self) -> &[u8] {
        &self.value[..self.value_len as usize]
    }

    /// Update the value.
    pub fn set_value(&mut self, val: &[u8]) -> Result<()> {
        if val.len() > 256 {
            return Err(Error::InvalidArgument);
        }
        self.value[..val.len()].copy_from_slice(val);
        self.value_len = val.len() as u16;
        Ok(())
    }
}

/// Maximum attributes per kobject.
pub const KOBJECT_MAX_ATTRS: usize = 32;

/// In-memory kobject.
pub struct Kobject {
    /// Stable unique ID.
    pub id: KobjectId,
    /// Kobject name (becomes the sysfs directory name).
    pub name: [u8; KOBJECT_NAME_MAX],
    pub name_len: u8,
    /// Parent kobject ID (ROOT for top-level objects).
    pub parent: KobjectId,
    /// Children.
    pub children: [KobjectId; KOBJECT_MAX_CHILDREN],
    pub child_count: u32,
    /// Reference count.
    pub ref_count: u32,
    /// Lifecycle state.
    pub state: KobjectState,
    /// Attributes array.
    pub attrs: [Option<KobjectAttr>; KOBJECT_MAX_ATTRS],
    pub attr_count: u8,
}

impl Kobject {
    /// Create a new initialized kobject.
    pub fn new(id: KobjectId, name: &[u8], parent: KobjectId) -> Result<Self> {
        if name.len() >= KOBJECT_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        let mut kobj = Self {
            id,
            name: [0u8; KOBJECT_NAME_MAX],
            name_len: name.len() as u8,
            parent,
            children: [KobjectId(0); KOBJECT_MAX_CHILDREN],
            child_count: 0,
            ref_count: 1,
            state: KobjectState::Initialized,
            attrs: [const { None }; KOBJECT_MAX_ATTRS],
            attr_count: 0,
        };
        kobj.name[..name.len()].copy_from_slice(name);
        Ok(kobj)
    }

    /// Name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Register in sysfs.
    pub fn register(&mut self) -> Result<()> {
        if self.state != KobjectState::Initialized {
            return Err(Error::InvalidArgument);
        }
        self.state = KobjectState::Active;
        Ok(())
    }

    /// Begin unregistration.
    pub fn unregister(&mut self) -> Result<()> {
        if self.state != KobjectState::Active {
            return Err(Error::InvalidArgument);
        }
        self.state = KobjectState::Removing;
        Ok(())
    }

    /// Add a child kobject ID.
    pub fn add_child(&mut self, child: KobjectId) -> Result<()> {
        if self.child_count as usize >= KOBJECT_MAX_CHILDREN {
            return Err(Error::OutOfMemory);
        }
        self.children[self.child_count as usize] = child;
        self.child_count += 1;
        Ok(())
    }

    /// Remove a child kobject ID.
    pub fn remove_child(&mut self, child: KobjectId) -> Result<()> {
        for i in 0..self.child_count as usize {
            if self.children[i] == child {
                let end = self.child_count as usize;
                self.children.copy_within(i + 1..end, i);
                self.child_count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Add an attribute.
    pub fn add_attr(&mut self, name: &[u8], mode: u16) -> Result<()> {
        if name.len() >= 64 || self.attr_count as usize >= KOBJECT_MAX_ATTRS {
            return Err(Error::OutOfMemory);
        }
        let mut attr = KobjectAttr {
            name: [0u8; 64],
            name_len: name.len() as u8,
            mode,
            value: [0u8; 256],
            value_len: 0,
        };
        attr.name[..name.len()].copy_from_slice(name);
        self.attrs[self.attr_count as usize] = Some(attr);
        self.attr_count += 1;
        Ok(())
    }

    /// Find an attribute by name.
    pub fn find_attr(&self, name: &[u8]) -> Option<&KobjectAttr> {
        self.attrs[..self.attr_count as usize]
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|a| a.name_bytes() == name)
    }

    /// Increment reference count.
    pub fn inc_ref(&mut self) {
        self.ref_count += 1;
    }

    /// Decrement reference count; returns `true` if it reached zero.
    pub fn dec_ref(&mut self) -> bool {
        if self.ref_count > 0 {
            self.ref_count -= 1;
        }
        if self.ref_count == 0 {
            self.state = KobjectState::Removed;
            true
        } else {
            false
        }
    }
}

/// Global kobject registry.
pub struct KobjectRegistry {
    objects: [Option<Kobject>; KOBJECT_MAX],
    count: usize,
    next_id: u32,
}

impl KobjectRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            objects: [const { None }; KOBJECT_MAX],
            count: 0,
            next_id: 1,
        }
    }

    /// Allocate a new kobject ID.
    fn alloc_id(&mut self) -> KobjectId {
        let id = KobjectId(self.next_id);
        self.next_id += 1;
        id
    }

    /// Create and register a kobject.
    pub fn create(&mut self, name: &[u8], parent: KobjectId) -> Result<KobjectId> {
        if self.count >= KOBJECT_MAX {
            return Err(Error::OutOfMemory);
        }
        let id = self.alloc_id();
        let kobj = Kobject::new(id, name, parent)?;
        for slot in &mut self.objects {
            if slot.is_none() {
                *slot = Some(kobj);
                self.count += 1;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up a kobject by ID.
    pub fn get(&self, id: KobjectId) -> Option<&Kobject> {
        self.objects
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|k| k.id == id)
    }

    /// Look up a mutable kobject by ID.
    pub fn get_mut(&mut self, id: KobjectId) -> Option<&mut Kobject> {
        self.objects
            .iter_mut()
            .filter_map(|s| s.as_mut())
            .find(|k| k.id == id)
    }

    /// Remove a kobject from the registry.
    pub fn remove(&mut self, id: KobjectId) -> Result<()> {
        for slot in &mut self.objects {
            if slot.as_ref().map(|k| k.id) == Some(id) {
                self.count -= 1;
                *slot = None;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Total registered kobjects.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for KobjectRegistry {
    fn default() -> Self {
        Self::new()
    }
}
