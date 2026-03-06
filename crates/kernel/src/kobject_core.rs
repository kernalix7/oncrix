// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel object model.
//!
//! The kobject is the fundamental building block of the kernel's
//! device model. Every device, driver, bus, and class has an
//! associated kobject that provides reference counting, sysfs
//! representation, and uevent notification.
//!
//! # Design
//!
//! ```text
//!   Kobject
//!   +------------------+
//!   | name             |
//!   | parent_idx       |
//!   | kset_idx         |
//!   | ktype_idx        |
//!   | ref_count        |
//!   | state_init       |
//!   | state_in_sysfs   |
//!   +------------------+
//!
//!   KobjType: defines release + sysfs_ops for a class of objects.
//!   Kset: a collection of kobjects (see kset.rs).
//! ```
//!
//! # Lifecycle
//!
//! 1. `kobject_init()` — initialize with a ktype.
//! 2. `kobject_add()` — add to parent/kset, generate uevent.
//! 3. `kobject_get()` / `kobject_put()` — reference counting.
//! 4. `kobject_del()` — remove from hierarchy.
//! 5. When refcount hits 0, the ktype's release callback is
//!    invoked.
//!
//! # Reference
//!
//! Linux `lib/kobject.c`, `include/linux/kobject.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum kobjects.
const MAX_KOBJECTS: usize = 512;

/// Maximum kobj types.
const MAX_KTYPES: usize = 64;

/// No parent/kset sentinel.
const NO_IDX: u32 = u32::MAX;

/// Maximum name length.
const MAX_NAME_LEN: usize = 64;

// ======================================================================
// UeventAction
// ======================================================================

/// Uevent action types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UeventAction {
    /// Device/object added.
    Add,
    /// Device/object removed.
    Remove,
    /// Device/object changed.
    Change,
    /// Device moved in hierarchy.
    Move,
    /// Device online.
    Online,
    /// Device offline.
    Offline,
    /// Device bound to driver.
    Bind,
    /// Device unbound from driver.
    Unbind,
}

// ======================================================================
// KobjType
// ======================================================================

/// Describes a class of kernel objects (their behaviors).
#[derive(Debug, Clone, Copy)]
pub struct KobjType {
    /// Type name.
    name: [u8; 32],
    /// Name length.
    name_len: usize,
    /// Whether this type slot is active.
    active: bool,
    /// Whether objects of this type appear in sysfs.
    sysfs_visible: bool,
    /// Default file permissions (octal).
    default_perms: u32,
}

impl KobjType {
    /// Creates a new empty type.
    pub const fn new() -> Self {
        Self {
            name: [0u8; 32],
            name_len: 0,
            active: false,
            sysfs_visible: true,
            default_perms: 0o644,
        }
    }

    /// Returns the type name (as bytes).
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns whether this type is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Returns whether sysfs-visible.
    pub fn sysfs_visible(&self) -> bool {
        self.sysfs_visible
    }

    /// Returns default permissions.
    pub fn default_perms(&self) -> u32 {
        self.default_perms
    }
}

// ======================================================================
// Kobject
// ======================================================================

/// A kernel object — the base of the device model.
pub struct Kobject {
    /// Object name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Parent kobject index (NO_IDX if root).
    parent_idx: u32,
    /// Kset index (NO_IDX if none).
    kset_idx: u32,
    /// KobjType index (NO_IDX if none).
    ktype_idx: u32,
    /// Reference count.
    ref_count: u32,
    /// Whether kobject_init has been called.
    state_initialized: bool,
    /// Whether registered in sysfs.
    state_in_sysfs: bool,
    /// Whether allocated (slot in use).
    allocated: bool,
    /// Generation counter for uevent sequencing.
    uevent_seq: u64,
    /// Last uevent action.
    last_uevent: Option<UeventAction>,
}

impl Kobject {
    /// Creates a new empty kobject.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            parent_idx: NO_IDX,
            kset_idx: NO_IDX,
            ktype_idx: NO_IDX,
            ref_count: 0,
            state_initialized: false,
            state_in_sysfs: false,
            allocated: false,
            uevent_seq: 0,
            last_uevent: None,
        }
    }

    /// Returns the object name (as bytes).
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns the parent index.
    pub fn parent_idx(&self) -> u32 {
        self.parent_idx
    }

    /// Returns the kset index.
    pub fn kset_idx(&self) -> u32 {
        self.kset_idx
    }

    /// Returns the ktype index.
    pub fn ktype_idx(&self) -> u32 {
        self.ktype_idx
    }

    /// Returns the reference count.
    pub fn ref_count(&self) -> u32 {
        self.ref_count
    }

    /// Returns whether initialized.
    pub fn is_initialized(&self) -> bool {
        self.state_initialized
    }

    /// Returns whether in sysfs.
    pub fn is_in_sysfs(&self) -> bool {
        self.state_in_sysfs
    }

    /// Returns the last uevent action.
    pub fn last_uevent(&self) -> Option<UeventAction> {
        self.last_uevent
    }

    /// Returns the uevent sequence number.
    pub fn uevent_seq(&self) -> u64 {
        self.uevent_seq
    }
}

// ======================================================================
// KobjectManager
// ======================================================================

/// Manages the global kobject pool and kobj types.
pub struct KobjectManager {
    /// Kobject pool.
    objects: [Kobject; MAX_KOBJECTS],
    /// Number of allocated objects.
    obj_count: usize,
    /// Kobj type pool.
    ktypes: [KobjType; MAX_KTYPES],
    /// Number of registered types.
    ktype_count: usize,
    /// Global uevent sequence counter.
    uevent_seq: u64,
}

impl KobjectManager {
    /// Creates a new empty manager.
    pub const fn new() -> Self {
        Self {
            objects: [const { Kobject::new() }; MAX_KOBJECTS],
            obj_count: 0,
            ktypes: [const { KobjType::new() }; MAX_KTYPES],
            ktype_count: 0,
            uevent_seq: 0,
        }
    }

    /// Registers a new kobj type.
    pub fn register_ktype(&mut self, name: &[u8], sysfs_visible: bool) -> Result<usize> {
        if self.ktype_count >= MAX_KTYPES {
            return Err(Error::OutOfMemory);
        }
        let idx = self
            .ktypes
            .iter()
            .position(|k| !k.active)
            .ok_or(Error::OutOfMemory)?;
        let copy_len = name.len().min(32);
        self.ktypes[idx].name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.ktypes[idx].name_len = copy_len;
        self.ktypes[idx].active = true;
        self.ktypes[idx].sysfs_visible = sysfs_visible;
        self.ktype_count += 1;
        Ok(idx)
    }

    /// Initializes a kobject (allocates a slot).
    pub fn kobject_init(&mut self, name: &[u8], ktype_idx: u32) -> Result<usize> {
        if self.obj_count >= MAX_KOBJECTS {
            return Err(Error::OutOfMemory);
        }
        if ktype_idx != NO_IDX {
            let ki = ktype_idx as usize;
            if ki >= MAX_KTYPES || !self.ktypes[ki].active {
                return Err(Error::InvalidArgument);
            }
        }
        let idx = self
            .objects
            .iter()
            .position(|o| !o.allocated)
            .ok_or(Error::OutOfMemory)?;
        let copy_len = name.len().min(MAX_NAME_LEN);
        self.objects[idx].name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.objects[idx].name_len = copy_len;
        self.objects[idx].ktype_idx = ktype_idx;
        self.objects[idx].ref_count = 1;
        self.objects[idx].state_initialized = true;
        self.objects[idx].allocated = true;
        self.obj_count += 1;
        Ok(idx)
    }

    /// Adds a kobject to the hierarchy (parent + kset).
    pub fn kobject_add(&mut self, idx: usize, parent_idx: u32, kset_idx: u32) -> Result<()> {
        if idx >= MAX_KOBJECTS || !self.objects[idx].allocated {
            return Err(Error::NotFound);
        }
        if !self.objects[idx].state_initialized {
            return Err(Error::InvalidArgument);
        }
        if parent_idx != NO_IDX {
            let pi = parent_idx as usize;
            if pi >= MAX_KOBJECTS || !self.objects[pi].allocated {
                return Err(Error::InvalidArgument);
            }
        }
        self.objects[idx].parent_idx = parent_idx;
        self.objects[idx].kset_idx = kset_idx;
        self.objects[idx].state_in_sysfs = true;
        self.send_uevent(idx, UeventAction::Add);
        Ok(())
    }

    /// Removes a kobject from the hierarchy.
    pub fn kobject_del(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_KOBJECTS || !self.objects[idx].allocated {
            return Err(Error::NotFound);
        }
        self.send_uevent(idx, UeventAction::Remove);
        self.objects[idx].state_in_sysfs = false;
        self.objects[idx].parent_idx = NO_IDX;
        self.objects[idx].kset_idx = NO_IDX;
        Ok(())
    }

    /// Increments the reference count.
    pub fn kobject_get(&mut self, idx: usize) -> Result<u32> {
        if idx >= MAX_KOBJECTS || !self.objects[idx].allocated {
            return Err(Error::NotFound);
        }
        self.objects[idx].ref_count = self.objects[idx]
            .ref_count
            .checked_add(1)
            .ok_or(Error::OutOfMemory)?;
        Ok(self.objects[idx].ref_count)
    }

    /// Decrements the reference count.
    ///
    /// When it reaches 0, the kobject is released.
    pub fn kobject_put(&mut self, idx: usize) -> Result<bool> {
        if idx >= MAX_KOBJECTS || !self.objects[idx].allocated {
            return Err(Error::NotFound);
        }
        if self.objects[idx].ref_count == 0 {
            return Err(Error::InvalidArgument);
        }
        self.objects[idx].ref_count -= 1;
        if self.objects[idx].ref_count == 0 {
            self.objects[idx] = Kobject::new();
            self.obj_count -= 1;
            return Ok(true);
        }
        Ok(false)
    }

    /// Creates and adds a kobject in one step.
    pub fn kobject_create_and_add(
        &mut self,
        name: &[u8],
        ktype_idx: u32,
        parent_idx: u32,
    ) -> Result<usize> {
        let idx = self.kobject_init(name, ktype_idx)?;
        self.kobject_add(idx, parent_idx, NO_IDX)?;
        Ok(idx)
    }

    /// Returns a reference to a kobject.
    pub fn get_object(&self, idx: usize) -> Result<&Kobject> {
        if idx >= MAX_KOBJECTS || !self.objects[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(&self.objects[idx])
    }

    /// Returns the number of allocated objects.
    pub fn obj_count(&self) -> usize {
        self.obj_count
    }

    /// Returns the number of registered types.
    pub fn ktype_count(&self) -> usize {
        self.ktype_count
    }

    /// Returns the global uevent sequence.
    pub fn uevent_seq(&self) -> u64 {
        self.uevent_seq
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Sends a uevent for a kobject.
    fn send_uevent(&mut self, idx: usize, action: UeventAction) {
        self.uevent_seq += 1;
        self.objects[idx].uevent_seq = self.uevent_seq;
        self.objects[idx].last_uevent = Some(action);
    }
}
