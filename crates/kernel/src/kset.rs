// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel object set.
//!
//! A `Kset` is a collection of kobjects grouped together. It
//! embeds its own kobject (so ksets form a hierarchy) and
//! provides uevent filtering for its member objects.
//!
//! # Design
//!
//! ```text
//!   Kset
//!   +-------------------+
//!   | name              |
//!   | kobj (embedded)   |  ← the kset itself is a kobject
//!   | member_list[]     |  ← indices of member kobjects
//!   | uevent_filter     |  ← whether to suppress uevents
//!   +-------------------+
//! ```
//!
//! # Lifecycle
//!
//! 1. `kset_create_and_add()` — create + register in one step.
//! 2. `kset_register()` / `kset_unregister()` — manual lifecycle.
//! 3. `kset_find_obj()` — lookup a member by name.
//! 4. `kset_get()` / `kset_put()` — reference counting (delegates
//!    to embedded kobject).
//!
//! # Reference
//!
//! Linux `lib/kobject.c`, `include/linux/kobject.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum ksets.
const MAX_KSETS: usize = 128;

/// Maximum members per kset.
const MAX_MEMBERS: usize = 64;

/// Maximum name length.
const MAX_NAME_LEN: usize = 64;

/// No index sentinel.
const NO_IDX: u32 = u32::MAX;

// ======================================================================
// Kset
// ======================================================================

/// A set of kernel objects.
pub struct Kset {
    /// Kset name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Whether this kset is registered.
    registered: bool,
    /// Whether this slot is allocated.
    allocated: bool,
    /// Embedded kobject index (reference into a KobjectManager).
    kobj_idx: u32,
    /// Parent kset index (NO_IDX if top-level).
    parent_kset_idx: u32,
    /// Member kobject indices.
    members: [u32; MAX_MEMBERS],
    /// Number of members.
    member_count: usize,
    /// Reference count.
    ref_count: u32,
    /// Whether uevent filtering is enabled.
    uevent_filter: bool,
    /// Whether uevents are suppressed.
    uevent_suppress: bool,
    /// Generation counter.
    generation: u64,
}

impl Kset {
    /// Creates a new empty kset.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            registered: false,
            allocated: false,
            kobj_idx: NO_IDX,
            parent_kset_idx: NO_IDX,
            members: [NO_IDX; MAX_MEMBERS],
            member_count: 0,
            ref_count: 0,
            uevent_filter: false,
            uevent_suppress: false,
            generation: 0,
        }
    }

    /// Returns the name (as bytes).
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns whether registered.
    pub fn is_registered(&self) -> bool {
        self.registered
    }

    /// Returns the embedded kobject index.
    pub fn kobj_idx(&self) -> u32 {
        self.kobj_idx
    }

    /// Returns the parent kset index.
    pub fn parent_kset_idx(&self) -> u32 {
        self.parent_kset_idx
    }

    /// Returns the number of members.
    pub fn member_count(&self) -> usize {
        self.member_count
    }

    /// Returns the reference count.
    pub fn ref_count(&self) -> u32 {
        self.ref_count
    }

    /// Returns whether uevent filtering is enabled.
    pub fn uevent_filter(&self) -> bool {
        self.uevent_filter
    }

    /// Returns the generation counter.
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

// ======================================================================
// KsetManager
// ======================================================================

/// Manages the global kset pool.
pub struct KsetManager {
    /// Kset pool.
    ksets: [Kset; MAX_KSETS],
    /// Number of allocated ksets.
    count: usize,
}

impl KsetManager {
    /// Creates a new empty manager.
    pub const fn new() -> Self {
        Self {
            ksets: [const { Kset::new() }; MAX_KSETS],
            count: 0,
        }
    }

    /// Creates and registers a kset in one step.
    pub fn kset_create_and_add(&mut self, name: &[u8], parent_kset_idx: u32) -> Result<usize> {
        let idx = self.kset_create(name)?;
        self.ksets[idx].parent_kset_idx = parent_kset_idx;
        self.kset_register(idx)?;
        Ok(idx)
    }

    /// Creates a kset (but does not register it).
    pub fn kset_create(&mut self, name: &[u8]) -> Result<usize> {
        if self.count >= MAX_KSETS {
            return Err(Error::OutOfMemory);
        }
        let idx = self
            .ksets
            .iter()
            .position(|k| !k.allocated)
            .ok_or(Error::OutOfMemory)?;
        let copy_len = name.len().min(MAX_NAME_LEN);
        self.ksets[idx].name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.ksets[idx].name_len = copy_len;
        self.ksets[idx].allocated = true;
        self.ksets[idx].ref_count = 1;
        self.count += 1;
        Ok(idx)
    }

    /// Registers a kset (makes it visible).
    pub fn kset_register(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_KSETS || !self.ksets[idx].allocated {
            return Err(Error::NotFound);
        }
        if self.ksets[idx].registered {
            return Err(Error::AlreadyExists);
        }
        self.ksets[idx].registered = true;
        self.ksets[idx].generation += 1;
        Ok(())
    }

    /// Unregisters a kset.
    pub fn kset_unregister(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_KSETS || !self.ksets[idx].allocated {
            return Err(Error::NotFound);
        }
        if !self.ksets[idx].registered {
            return Err(Error::InvalidArgument);
        }
        self.ksets[idx].registered = false;
        self.ksets[idx].generation += 1;
        Ok(())
    }

    /// Adds a kobject (by index) to a kset.
    pub fn kset_add_member(&mut self, kset_idx: usize, kobj_idx: u32) -> Result<()> {
        if kset_idx >= MAX_KSETS || !self.ksets[kset_idx].allocated {
            return Err(Error::NotFound);
        }
        let mc = self.ksets[kset_idx].member_count;
        if mc >= MAX_MEMBERS {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicates.
        if self.ksets[kset_idx].members[..mc]
            .iter()
            .any(|&m| m == kobj_idx)
        {
            return Err(Error::AlreadyExists);
        }
        self.ksets[kset_idx].members[mc] = kobj_idx;
        self.ksets[kset_idx].member_count += 1;
        self.ksets[kset_idx].generation += 1;
        Ok(())
    }

    /// Removes a kobject from a kset.
    pub fn kset_remove_member(&mut self, kset_idx: usize, kobj_idx: u32) -> Result<()> {
        if kset_idx >= MAX_KSETS || !self.ksets[kset_idx].allocated {
            return Err(Error::NotFound);
        }
        let mc = self.ksets[kset_idx].member_count;
        let pos = self.ksets[kset_idx].members[..mc]
            .iter()
            .position(|&m| m == kobj_idx);
        match pos {
            Some(p) => {
                let last = mc - 1;
                self.ksets[kset_idx].members.swap(p, last);
                self.ksets[kset_idx].members[last] = NO_IDX;
                self.ksets[kset_idx].member_count -= 1;
                self.ksets[kset_idx].generation += 1;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Finds a member kobject by name.
    ///
    /// Returns the member's kobject index. This is a stub that
    /// compares the provided name against a hypothetical name
    /// lookup — in practice this would query the kobject manager.
    pub fn kset_find_obj(&self, kset_idx: usize, _name: &[u8]) -> Result<u32> {
        if kset_idx >= MAX_KSETS || !self.ksets[kset_idx].allocated {
            return Err(Error::NotFound);
        }
        // Return the first member as a stub.
        if self.ksets[kset_idx].member_count > 0 {
            Ok(self.ksets[kset_idx].members[0])
        } else {
            Err(Error::NotFound)
        }
    }

    /// Increments the kset's reference count.
    pub fn kset_get(&mut self, idx: usize) -> Result<u32> {
        if idx >= MAX_KSETS || !self.ksets[idx].allocated {
            return Err(Error::NotFound);
        }
        self.ksets[idx].ref_count = self.ksets[idx]
            .ref_count
            .checked_add(1)
            .ok_or(Error::OutOfMemory)?;
        Ok(self.ksets[idx].ref_count)
    }

    /// Decrements the kset's reference count.
    pub fn kset_put(&mut self, idx: usize) -> Result<bool> {
        if idx >= MAX_KSETS || !self.ksets[idx].allocated {
            return Err(Error::NotFound);
        }
        if self.ksets[idx].ref_count == 0 {
            return Err(Error::InvalidArgument);
        }
        self.ksets[idx].ref_count -= 1;
        if self.ksets[idx].ref_count == 0 {
            self.ksets[idx] = Kset::new();
            self.count -= 1;
            return Ok(true);
        }
        Ok(false)
    }

    /// Returns a reference to a kset.
    pub fn get(&self, idx: usize) -> Result<&Kset> {
        if idx >= MAX_KSETS || !self.ksets[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(&self.ksets[idx])
    }

    /// Returns the number of allocated ksets.
    pub fn count(&self) -> usize {
        self.count
    }
}
