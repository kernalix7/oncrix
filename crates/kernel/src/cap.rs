// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Capability-based security system.
//!
//! Capabilities are unforgeable tokens that grant specific permissions
//! to kernel objects (IPC endpoints, memory regions, processes, etc.).
//! Every operation on a kernel object requires presenting a valid
//! capability, replacing traditional UID/GID permission checks.
//!
//! This is a core security mechanism of the ONCRIX microkernel:
//! - Capabilities are passed explicitly (no ambient authority)
//! - Capabilities can be attenuated (reduced permissions) but never amplified
//! - Revocation is supported via generation counters
//!
//! Design inspired by seL4 capabilities and Plan 9 file descriptors.
//!
//! Reference: seL4 Reference Manual §2 (Capability-based Access Control).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Capability rights (bitfield)
// ---------------------------------------------------------------------------

/// Permission bits for a capability.
///
/// Rights are a bitmask — capabilities can be attenuated by clearing
/// bits, but never amplified (new bits cannot be set).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Rights(u32);

impl Rights {
    /// No permissions.
    pub const NONE: Self = Self(0);
    /// Read / receive permission.
    pub const READ: Self = Self(1 << 0);
    /// Write / send permission.
    pub const WRITE: Self = Self(1 << 1);
    /// Execute permission.
    pub const EXECUTE: Self = Self(1 << 2);
    /// Grant: can derive sub-capabilities.
    pub const GRANT: Self = Self(1 << 3);
    /// Revoke: can invalidate derived capabilities.
    pub const REVOKE: Self = Self(1 << 4);
    /// Full permissions.
    pub const ALL: Self = Self(0x1F);

    /// Create rights from a raw bitmask.
    pub const fn from_raw(bits: u32) -> Self {
        Self(bits)
    }

    /// Get the raw bitmask.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Check if `self` includes all of `required`.
    pub const fn contains(self, required: Rights) -> bool {
        (self.0 & required.0) == required.0
    }

    /// Attenuate: mask rights to a subset.
    ///
    /// The result has at most the rights present in both `self` and `mask`.
    pub const fn attenuate(self, mask: Rights) -> Self {
        Self(self.0 & mask.0)
    }

    /// Check if this capability has no rights.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl core::fmt::Display for Rights {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut first = true;
        let flags = [
            (Self::READ, "read"),
            (Self::WRITE, "write"),
            (Self::EXECUTE, "exec"),
            (Self::GRANT, "grant"),
            (Self::REVOKE, "revoke"),
        ];
        for (flag, name) in &flags {
            if self.contains(*flag) {
                if !first {
                    write!(f, "|")?;
                }
                write!(f, "{name}")?;
                first = false;
            }
        }
        if first {
            write!(f, "none")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Object type
// ---------------------------------------------------------------------------

/// The kind of kernel object a capability refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectType {
    /// Null / invalid capability.
    Null,
    /// IPC endpoint.
    Endpoint,
    /// IPC async notification port.
    Notification,
    /// Memory region (page or frame).
    Memory,
    /// Thread control block.
    Thread,
    /// Process (CSpace root).
    Process,
    /// IRQ handler.
    Irq,
    /// Device MMIO region.
    Device,
}

impl core::fmt::Display for ObjectType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Null => write!(f, "null"),
            Self::Endpoint => write!(f, "endpoint"),
            Self::Notification => write!(f, "notification"),
            Self::Memory => write!(f, "memory"),
            Self::Thread => write!(f, "thread"),
            Self::Process => write!(f, "process"),
            Self::Irq => write!(f, "irq"),
            Self::Device => write!(f, "device"),
        }
    }
}

// ---------------------------------------------------------------------------
// Capability
// ---------------------------------------------------------------------------

/// A capability — an unforgeable token granting access to a kernel object.
#[derive(Debug, Clone, Copy)]
pub struct Capability {
    /// Type of kernel object.
    pub obj_type: ObjectType,
    /// Kernel-internal object identifier.
    pub obj_id: u64,
    /// Permitted operations.
    pub rights: Rights,
    /// Generation counter for revocation.
    ///
    /// When the generation in the capability doesn't match the
    /// generation in the kernel object, the capability is stale.
    pub generation: u32,
}

impl Capability {
    /// Create a null capability (no access).
    pub const fn null() -> Self {
        Self {
            obj_type: ObjectType::Null,
            obj_id: 0,
            rights: Rights::NONE,
            generation: 0,
        }
    }

    /// Create a new capability.
    pub const fn new(obj_type: ObjectType, obj_id: u64, rights: Rights, generation: u32) -> Self {
        Self {
            obj_type,
            obj_id,
            rights,
            generation,
        }
    }

    /// Check if this is a null (invalid) capability.
    pub const fn is_null(&self) -> bool {
        matches!(self.obj_type, ObjectType::Null)
    }

    /// Derive a sub-capability with reduced rights.
    ///
    /// Requires the `GRANT` right. The derived capability has at most
    /// the intersection of the original rights and `new_rights`.
    pub fn derive(&self, new_rights: Rights) -> Result<Self> {
        if !self.rights.contains(Rights::GRANT) {
            return Err(Error::PermissionDenied);
        }
        Ok(Self {
            obj_type: self.obj_type,
            obj_id: self.obj_id,
            rights: self.rights.attenuate(new_rights),
            generation: self.generation,
        })
    }

    /// Check that this capability has the required rights.
    pub fn check_rights(&self, required: Rights) -> Result<()> {
        if self.rights.contains(required) {
            Ok(())
        } else {
            Err(Error::PermissionDenied)
        }
    }
}

// ---------------------------------------------------------------------------
// Capability space (CSpace)
// ---------------------------------------------------------------------------

/// Maximum capabilities per process.
const MAX_CAPS_PER_PROCESS: usize = 256;

/// A capability space — the set of capabilities held by a process.
///
/// Indexed by capability slot number (analogous to file descriptors).
/// Slot 0 is always the process's own capability (self-reference).
pub struct CSpace {
    /// Capability slots.
    slots: [Option<Capability>; MAX_CAPS_PER_PROCESS],
    /// Number of occupied slots.
    count: usize,
}

impl Default for CSpace {
    fn default() -> Self {
        Self::new()
    }
}

impl CSpace {
    /// Create an empty capability space.
    pub const fn new() -> Self {
        const NONE_CAP: Option<Capability> = None;
        Self {
            slots: [NONE_CAP; MAX_CAPS_PER_PROCESS],
            count: 0,
        }
    }

    /// Insert a capability, returning the slot index.
    pub fn insert(&mut self, cap: Capability) -> Result<usize> {
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(cap);
                self.count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up a capability by slot index.
    pub fn get(&self, slot: usize) -> Result<&Capability> {
        self.slots
            .get(slot)
            .and_then(|s| s.as_ref())
            .ok_or(Error::InvalidArgument)
    }

    /// Remove a capability from a slot.
    pub fn remove(&mut self, slot: usize) -> Result<Capability> {
        let cap = self
            .slots
            .get_mut(slot)
            .and_then(|s| s.take())
            .ok_or(Error::InvalidArgument)?;
        self.count = self.count.saturating_sub(1);
        Ok(cap)
    }

    /// Verify that a slot holds a capability of the expected type
    /// with the required rights, and that the generation matches.
    pub fn validate(
        &self,
        slot: usize,
        expected_type: ObjectType,
        required_rights: Rights,
        current_generation: u32,
    ) -> Result<&Capability> {
        let cap = self.get(slot)?;
        if cap.obj_type != expected_type {
            return Err(Error::InvalidArgument);
        }
        cap.check_rights(required_rights)?;
        if cap.generation != current_generation {
            return Err(Error::PermissionDenied);
        }
        Ok(cap)
    }

    /// Duplicate a capability into a new slot (requires GRANT right).
    pub fn duplicate(&mut self, src_slot: usize, new_rights: Rights) -> Result<usize> {
        let src = *self.get(src_slot)?;
        let derived = src.derive(new_rights)?;
        self.insert(derived)
    }

    /// Number of occupied slots.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Check if a slot is occupied.
    pub fn is_valid(&self, slot: usize) -> bool {
        self.slots.get(slot).is_some_and(|s| s.is_some())
    }

    /// Clear all capabilities (used on process exit).
    pub fn clear(&mut self) {
        for slot in self.slots.iter_mut() {
            *slot = None;
        }
        self.count = 0;
    }
}

impl core::fmt::Debug for CSpace {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CSpace")
            .field("count", &self.count)
            .field("capacity", &MAX_CAPS_PER_PROCESS)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Capability revocation registry
// ---------------------------------------------------------------------------

/// Maximum tracked objects for revocation.
const MAX_REVOCABLE_OBJECTS: usize = 256;

/// An entry in the revocation registry.
#[derive(Debug, Clone, Copy)]
struct RevocationEntry {
    /// Object ID.
    obj_id: u64,
    /// Object type.
    obj_type: ObjectType,
    /// Current generation (increment to revoke).
    generation: u32,
}

/// Global revocation registry.
///
/// Tracks the current generation of revocable kernel objects.
/// When a capability's generation doesn't match, access is denied.
pub struct RevocationRegistry {
    /// Object entries.
    entries: [Option<RevocationEntry>; MAX_REVOCABLE_OBJECTS],
    /// Number of tracked objects.
    count: usize,
}

impl Default for RevocationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RevocationRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const NONE_ENTRY: Option<RevocationEntry> = None;
        Self {
            entries: [NONE_ENTRY; MAX_REVOCABLE_OBJECTS],
            count: 0,
        }
    }

    /// Register a new revocable object. Returns its initial generation (0).
    pub fn register(&mut self, obj_type: ObjectType, obj_id: u64) -> Result<u32> {
        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(RevocationEntry {
                    obj_id,
                    obj_type,
                    generation: 0,
                });
                self.count += 1;
                return Ok(0);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Revoke all capabilities to an object by incrementing its generation.
    ///
    /// Returns the new generation number.
    pub fn revoke(&mut self, obj_type: ObjectType, obj_id: u64) -> Result<u32> {
        for slot in self.entries.iter_mut().flatten() {
            if slot.obj_type == obj_type && slot.obj_id == obj_id {
                slot.generation = slot.generation.wrapping_add(1);
                return Ok(slot.generation);
            }
        }
        Err(Error::NotFound)
    }

    /// Get the current generation for an object.
    pub fn current_generation(&self, obj_type: ObjectType, obj_id: u64) -> Result<u32> {
        for entry in self.entries.iter().flatten() {
            if entry.obj_type == obj_type && entry.obj_id == obj_id {
                return Ok(entry.generation);
            }
        }
        Err(Error::NotFound)
    }

    /// Remove an object from tracking (on object destruction).
    pub fn unregister(&mut self, obj_type: ObjectType, obj_id: u64) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if let Some(entry) = slot {
                if entry.obj_type == obj_type && entry.obj_id == obj_id {
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Number of tracked objects.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl core::fmt::Debug for RevocationRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RevocationRegistry")
            .field("count", &self.count)
            .field("capacity", &MAX_REVOCABLE_OBJECTS)
            .finish()
    }
}
