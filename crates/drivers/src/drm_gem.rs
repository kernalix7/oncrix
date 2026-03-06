// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DRM GEM (Graphics Execution Manager) memory management for ONCRIX.
//!
//! Provides GPU buffer object management including GEM object allocation,
//! handle lookup table, mmap offset management, create/open/close lifecycle,
//! pinning for scanout or DMA, flink global names, PRIME fd import/export,
//! and virtual address mapping.
//!
//! # Architecture
//!
//! - **GemObject** — GPU-visible memory buffer with handle and backing
//! - **GemHandle** — per-process handle referencing a GEM object
//! - **GemMmapOffset** — fake mmap offset for user-space mapping
//! - **GemFlink** — global name for cross-process GEM sharing
//! - **GemPrimeEntry** — PRIME DMA-BUF export/import tracking
//! - **GemHandleTable** — per-process handle-to-object mapping
//! - **GemObjectPool** — device-level GEM object storage
//! - **GemRegistry** — manages GEM pools across DRM devices
//!
//! Reference: Linux `drivers/gpu/drm/drm_gem.c`, `include/drm/drm_gem.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum GEM objects per device.
const MAX_GEM_OBJECTS: usize = 256;

/// Maximum handles per process.
const MAX_HANDLES: usize = 128;

/// Maximum flink global names per device.
const MAX_FLINKS: usize = 64;

/// Maximum PRIME entries per device.
const MAX_PRIME_ENTRIES: usize = 32;

/// Maximum DRM devices in the registry.
const MAX_DEVICES: usize = 4;

/// Page size for mmap offset alignment.
const PAGE_SIZE: usize = 4096;

/// Invalid handle sentinel.
pub const GEM_HANDLE_INVALID: u32 = 0;

// ---------------------------------------------------------------------------
// GemObjectFlags
// ---------------------------------------------------------------------------

/// Flags for GEM object properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GemObjectFlags(u32);

impl GemObjectFlags {
    /// No flags set.
    pub const NONE: Self = Self(0);
    /// Object is pinned (cannot be evicted).
    pub const PINNED: Self = Self(1 << 0);
    /// Object is mapped into kernel virtual address space.
    pub const VMAPPED: Self = Self(1 << 1);
    /// Object is exported via PRIME.
    pub const PRIME_EXPORTED: Self = Self(1 << 2);
    /// Object has a flink global name.
    pub const FLINKED: Self = Self(1 << 3);
    /// Object is purgeable (can be freed under memory pressure).
    pub const PURGEABLE: Self = Self(1 << 4);

    /// Returns whether the given flag is set.
    pub fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 != 0
    }

    /// Sets a flag.
    pub fn set(&mut self, flag: Self) {
        self.0 |= flag.0;
    }

    /// Clears a flag.
    pub fn clear(&mut self, flag: Self) {
        self.0 &= !flag.0;
    }
}

// ---------------------------------------------------------------------------
// GemObject
// ---------------------------------------------------------------------------

/// A GPU-visible memory buffer managed by the GEM subsystem.
///
/// Each GEM object has a unique ID, a size, backing store address,
/// reference count, and flags tracking its state (pinned, mapped,
/// exported, etc.).
#[derive(Debug, Clone, Copy)]
pub struct GemObject {
    /// Unique object identifier (device-scoped).
    pub id: u32,
    /// Size in bytes (page-aligned).
    pub size: usize,
    /// Physical/bus address of the backing store.
    pub backing_addr: u64,
    /// Virtual address if vmapped, zero otherwise.
    pub vmap_addr: u64,
    /// Reference count.
    pub refcount: u32,
    /// Object flags.
    pub flags: GemObjectFlags,
    /// Fake mmap offset for user-space mapping.
    pub mmap_offset: u64,
    /// Flink global name (0 = none).
    pub flink_name: u32,
    /// PRIME fd (negative = not exported).
    pub prime_fd: i32,
    /// Whether this object slot is in use.
    pub active: bool,
}

/// Constant empty GEM object for array initialisation.
const EMPTY_GEM: GemObject = GemObject {
    id: 0,
    size: 0,
    backing_addr: 0,
    vmap_addr: 0,
    refcount: 0,
    flags: GemObjectFlags::NONE,
    mmap_offset: 0,
    flink_name: 0,
    prime_fd: -1,
    active: false,
};

impl GemObject {
    /// Creates a new GEM object with the given size.
    ///
    /// The size is rounded up to the next page boundary.
    pub fn new(id: u32, size: usize) -> Self {
        let aligned = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        Self {
            id,
            size: aligned,
            backing_addr: 0,
            vmap_addr: 0,
            refcount: 1,
            flags: GemObjectFlags::NONE,
            mmap_offset: (id as u64) * PAGE_SIZE as u64,
            flink_name: 0,
            prime_fd: -1,
            active: true,
        }
    }

    /// Increments the reference count.
    pub fn get_ref(&mut self) {
        self.refcount = self.refcount.saturating_add(1);
    }

    /// Decrements the reference count. Returns `true` if it reached zero.
    pub fn put_ref(&mut self) -> bool {
        self.refcount = self.refcount.saturating_sub(1);
        self.refcount == 0
    }

    /// Pins the object (prevents eviction).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if already pinned.
    pub fn pin(&mut self) -> Result<()> {
        if self.flags.contains(GemObjectFlags::PINNED) {
            return Err(Error::Busy);
        }
        self.flags.set(GemObjectFlags::PINNED);
        Ok(())
    }

    /// Unpins the object.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if not pinned.
    pub fn unpin(&mut self) -> Result<()> {
        if !self.flags.contains(GemObjectFlags::PINNED) {
            return Err(Error::InvalidArgument);
        }
        self.flags.clear(GemObjectFlags::PINNED);
        Ok(())
    }

    /// Maps the object into kernel virtual address space.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if already vmapped.
    pub fn vmap(&mut self, addr: u64) -> Result<()> {
        if self.flags.contains(GemObjectFlags::VMAPPED) {
            return Err(Error::Busy);
        }
        self.vmap_addr = addr;
        self.flags.set(GemObjectFlags::VMAPPED);
        Ok(())
    }

    /// Unmaps the object from kernel virtual address space.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if not vmapped.
    pub fn vunmap(&mut self) -> Result<()> {
        if !self.flags.contains(GemObjectFlags::VMAPPED) {
            return Err(Error::InvalidArgument);
        }
        self.vmap_addr = 0;
        self.flags.clear(GemObjectFlags::VMAPPED);
        Ok(())
    }

    /// Sets the flink global name for cross-process sharing.
    pub fn set_flink(&mut self, name: u32) {
        self.flink_name = name;
        self.flags.set(GemObjectFlags::FLINKED);
    }

    /// Marks the object as PRIME-exported with the given fd.
    pub fn set_prime_export(&mut self, fd: i32) {
        self.prime_fd = fd;
        self.flags.set(GemObjectFlags::PRIME_EXPORTED);
    }
}

// ---------------------------------------------------------------------------
// GemHandle
// ---------------------------------------------------------------------------

/// A per-process handle referencing a GEM object.
#[derive(Debug, Clone, Copy)]
pub struct GemHandle {
    /// Handle value (process-scoped, nonzero).
    pub handle: u32,
    /// Referenced GEM object ID.
    pub object_id: u32,
    /// Whether this handle slot is in use.
    pub active: bool,
}

/// Constant empty handle for array initialisation.
const EMPTY_HANDLE: GemHandle = GemHandle {
    handle: 0,
    object_id: 0,
    active: false,
};

// ---------------------------------------------------------------------------
// GemFlink
// ---------------------------------------------------------------------------

/// A flink global name entry.
#[derive(Debug, Clone, Copy)]
pub struct GemFlink {
    /// Global name.
    pub name: u32,
    /// Referenced GEM object ID.
    pub object_id: u32,
    /// Device ID owning the object.
    pub device_id: u32,
    /// Whether this entry is active.
    pub active: bool,
}

/// Constant empty flink for array initialisation.
const EMPTY_FLINK: GemFlink = GemFlink {
    name: 0,
    object_id: 0,
    device_id: 0,
    active: false,
};

// ---------------------------------------------------------------------------
// GemPrimeEntry
// ---------------------------------------------------------------------------

/// PRIME DMA-BUF export/import tracking entry.
#[derive(Debug, Clone, Copy)]
pub struct GemPrimeEntry {
    /// File descriptor for the DMA-BUF.
    pub fd: i32,
    /// Referenced GEM object ID.
    pub object_id: u32,
    /// Device ID owning the object.
    pub device_id: u32,
    /// Whether this is an export (true) or import (false).
    pub is_export: bool,
    /// Whether this entry is active.
    pub active: bool,
}

/// Constant empty PRIME entry for array initialisation.
const EMPTY_PRIME: GemPrimeEntry = GemPrimeEntry {
    fd: -1,
    object_id: 0,
    device_id: 0,
    is_export: false,
    active: false,
};

// ---------------------------------------------------------------------------
// GemHandleTable
// ---------------------------------------------------------------------------

/// Per-process handle-to-object lookup table.
pub struct GemHandleTable {
    /// Handle entries.
    handles: [GemHandle; MAX_HANDLES],
    /// Number of active handles.
    count: usize,
    /// Next handle value to assign.
    next_handle: u32,
}

impl GemHandleTable {
    /// Creates a new empty handle table.
    pub const fn new() -> Self {
        Self {
            handles: [EMPTY_HANDLE; MAX_HANDLES],
            count: 0,
            next_handle: 1, // Handle 0 is invalid
        }
    }

    /// Creates a handle for a GEM object.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn create(&mut self, object_id: u32) -> Result<u32> {
        if self.count >= MAX_HANDLES {
            return Err(Error::OutOfMemory);
        }
        let handle = self.next_handle;
        self.next_handle = self.next_handle.wrapping_add(1);
        if self.next_handle == GEM_HANDLE_INVALID {
            self.next_handle = 1;
        }
        for slot in self.handles.iter_mut() {
            if !slot.active {
                *slot = GemHandle {
                    handle,
                    object_id,
                    active: true,
                };
                self.count += 1;
                return Ok(handle);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Looks up a handle and returns the associated object ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the handle is not found.
    pub fn lookup(&self, handle: u32) -> Result<u32> {
        for h in &self.handles {
            if h.active && h.handle == handle {
                return Ok(h.object_id);
            }
        }
        Err(Error::NotFound)
    }

    /// Closes a handle.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the handle is not found.
    pub fn close(&mut self, handle: u32) -> Result<u32> {
        for h in self.handles.iter_mut() {
            if h.active && h.handle == handle {
                h.active = false;
                self.count -= 1;
                return Ok(h.object_id);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of active handles.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ---------------------------------------------------------------------------
// GemObjectPool
// ---------------------------------------------------------------------------

/// Device-level GEM object storage and management.
///
/// Stores all GEM objects for a single DRM device, manages flink
/// names and PRIME entries, and provides create/open/close lifecycle.
pub struct GemObjectPool {
    /// Device identifier.
    pub device_id: u32,
    /// GEM object storage.
    objects: [GemObject; MAX_GEM_OBJECTS],
    /// Number of active objects.
    count: usize,
    /// Next object ID to assign.
    next_id: u32,
    /// Flink global name table.
    flinks: [GemFlink; MAX_FLINKS],
    /// Number of active flinks.
    flink_count: usize,
    /// Next flink name to assign.
    next_flink_name: u32,
    /// PRIME export/import entries.
    primes: [GemPrimeEntry; MAX_PRIME_ENTRIES],
    /// Number of active PRIME entries.
    prime_count: usize,
}

impl GemObjectPool {
    /// Creates a new empty object pool for the given device.
    pub const fn new(device_id: u32) -> Self {
        Self {
            device_id,
            objects: [EMPTY_GEM; MAX_GEM_OBJECTS],
            count: 0,
            next_id: 1,
            flinks: [EMPTY_FLINK; MAX_FLINKS],
            flink_count: 0,
            next_flink_name: 1,
            primes: [EMPTY_PRIME; MAX_PRIME_ENTRIES],
            prime_count: 0,
        }
    }

    /// Creates a new GEM object with the given size.
    ///
    /// Returns the object ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the pool is full, or
    /// [`Error::InvalidArgument`] if size is zero.
    pub fn create(&mut self, size: usize) -> Result<u32> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_GEM_OBJECTS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let obj = GemObject::new(id, size);
        for slot in self.objects.iter_mut() {
            if !slot.active {
                *slot = obj;
                self.count += 1;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Opens (increments reference to) an existing GEM object.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the object does not exist.
    pub fn open(&mut self, object_id: u32) -> Result<()> {
        for obj in self.objects.iter_mut() {
            if obj.active && obj.id == object_id {
                obj.get_ref();
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Closes (decrements reference to) a GEM object.
    ///
    /// The object is freed when its reference count reaches zero.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the object does not exist.
    pub fn close(&mut self, object_id: u32) -> Result<()> {
        for obj in self.objects.iter_mut() {
            if obj.active && obj.id == object_id {
                if obj.put_ref() {
                    obj.active = false;
                    self.count -= 1;
                    // Remove associated flink
                    for fl in self.flinks.iter_mut() {
                        if fl.active && fl.object_id == object_id {
                            fl.active = false;
                            self.flink_count -= 1;
                        }
                    }
                    // Remove associated PRIME entries
                    for pe in self.primes.iter_mut() {
                        if pe.active && pe.object_id == object_id {
                            pe.active = false;
                            self.prime_count -= 1;
                        }
                    }
                }
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a reference to a GEM object by ID.
    pub fn get(&self, object_id: u32) -> Result<&GemObject> {
        for obj in &self.objects {
            if obj.active && obj.id == object_id {
                return Ok(obj);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a mutable reference to a GEM object by ID.
    pub fn get_mut(&mut self, object_id: u32) -> Result<&mut GemObject> {
        for obj in self.objects.iter_mut() {
            if obj.active && obj.id == object_id {
                return Ok(obj);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the mmap offset for a GEM object.
    pub fn mmap_offset(&self, object_id: u32) -> Result<u64> {
        let obj = self.get(object_id)?;
        Ok(obj.mmap_offset)
    }

    /// Creates a flink global name for a GEM object.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the flink table is full,
    /// [`Error::AlreadyExists`] if the object already has a flink, or
    /// [`Error::NotFound`] if the object does not exist.
    pub fn flink(&mut self, object_id: u32) -> Result<u32> {
        // Check object exists and doesn't already have a flink
        let obj = self.get(object_id)?;
        if obj.flags.contains(GemObjectFlags::FLINKED) {
            return Ok(obj.flink_name);
        }
        if self.flink_count >= MAX_FLINKS {
            return Err(Error::OutOfMemory);
        }
        let name = self.next_flink_name;
        self.next_flink_name = self.next_flink_name.wrapping_add(1);

        // Update the object
        let obj_mut = self.get_mut(object_id)?;
        obj_mut.set_flink(name);

        // Add flink entry
        for fl in self.flinks.iter_mut() {
            if !fl.active {
                *fl = GemFlink {
                    name,
                    object_id,
                    device_id: self.device_id,
                    active: true,
                };
                self.flink_count += 1;
                return Ok(name);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Looks up a GEM object by flink name.
    pub fn lookup_flink(&self, name: u32) -> Result<u32> {
        for fl in &self.flinks {
            if fl.active && fl.name == name {
                return Ok(fl.object_id);
            }
        }
        Err(Error::NotFound)
    }

    /// Exports a GEM object via PRIME, returning a fd.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the PRIME table is full.
    pub fn prime_export(&mut self, object_id: u32, fd: i32) -> Result<()> {
        // Verify object exists
        let _ = self.get(object_id)?;
        if self.prime_count >= MAX_PRIME_ENTRIES {
            return Err(Error::OutOfMemory);
        }

        let obj = self.get_mut(object_id)?;
        obj.set_prime_export(fd);

        for pe in self.primes.iter_mut() {
            if !pe.active {
                *pe = GemPrimeEntry {
                    fd,
                    object_id,
                    device_id: self.device_id,
                    is_export: true,
                    active: true,
                };
                self.prime_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Imports a PRIME DMA-BUF as a GEM object.
    ///
    /// Returns the new object ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the pool or PRIME table is full.
    pub fn prime_import(&mut self, fd: i32, size: usize) -> Result<u32> {
        let obj_id = self.create(size)?;
        if self.prime_count >= MAX_PRIME_ENTRIES {
            // Roll back creation
            let _ = self.close(obj_id);
            return Err(Error::OutOfMemory);
        }
        for pe in self.primes.iter_mut() {
            if !pe.active {
                *pe = GemPrimeEntry {
                    fd,
                    object_id: obj_id,
                    device_id: self.device_id,
                    is_export: false,
                    active: true,
                };
                self.prime_count += 1;
                return Ok(obj_id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns the number of active GEM objects.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no objects are stored.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the total memory used by all active objects in bytes.
    pub fn total_memory(&self) -> usize {
        let mut total = 0;
        for obj in &self.objects {
            if obj.active {
                total += obj.size;
            }
        }
        total
    }
}

// ---------------------------------------------------------------------------
// GemRegistry
// ---------------------------------------------------------------------------

/// Registry managing GEM object pools across multiple DRM devices.
pub struct GemRegistry {
    /// Per-device GEM pools.
    pools: [Option<GemObjectPool>; MAX_DEVICES],
    /// Number of registered pools.
    count: usize,
}

impl GemRegistry {
    /// Creates a new empty registry.
    pub const fn new() -> Self {
        Self {
            pools: [const { None }; MAX_DEVICES],
            count: 0,
        }
    }

    /// Registers a GEM pool for a DRM device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a pool for the device already exists.
    pub fn register(&mut self, pool: GemObjectPool) -> Result<()> {
        for slot in self.pools.iter().flatten() {
            if slot.device_id == pool.device_id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in self.pools.iter_mut() {
            if slot.is_none() {
                *slot = Some(pool);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns a reference to a pool by device ID.
    pub fn get(&self, device_id: u32) -> Result<&GemObjectPool> {
        for slot in self.pools.iter().flatten() {
            if slot.device_id == device_id {
                return Ok(slot);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a mutable reference to a pool by device ID.
    pub fn get_mut(&mut self, device_id: u32) -> Result<&mut GemObjectPool> {
        for slot in self.pools.iter_mut() {
            if let Some(p) = slot {
                if p.device_id == device_id {
                    return Ok(p);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of registered pools.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no pools are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
