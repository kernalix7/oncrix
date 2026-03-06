// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX shared memory objects (`shm_open`, `shm_unlink`,
//! `ftruncate`, `mmap`).
//!
//! This module implements named shared memory regions that can be
//! mapped into multiple process address spaces for zero-copy IPC.
//! The current implementation uses a fixed inline page (4 KiB) per
//! object; a production version would allocate physical pages from
//! the page allocator.
//!
//! Reference: POSIX.1-2024 `sys/mman.h`, `shm_open(3)`.

use oncrix_lib::{Error, Result};

// -- Constants -------------------------------------------------------

/// Maximum number of shared memory objects system-wide.
const MAX_SHM_OBJECTS: usize = 64;

/// Maximum length of a shared memory object name (bytes).
const MAX_SHM_NAME: usize = 32;

/// Maximum size of a single shared memory object (16 MiB).
const MAX_SHM_SIZE: u64 = 16 * 1024 * 1024;

/// Inline data page size (bytes).
const _INLINE_PAGE: usize = 4096;

/// Open flag: create object if it does not exist.
const O_CREAT: i32 = 0x40;

/// Open flag: fail if object already exists (with `O_CREAT`).
const O_EXCL: i32 = 0x80;

/// Open flag: open for reading only.
const _O_RDONLY: i32 = 0;

/// Open flag: open for reading and writing.
const _O_RDWR: i32 = 2;

/// Open flag: truncate size to zero on open.
const O_TRUNC: i32 = 0x200;

// -- ShmObject -------------------------------------------------------

/// A single POSIX shared memory object.
#[derive(Clone)]
struct ShmObject {
    /// Object name (UTF-8 bytes, no NUL terminator required).
    name: [u8; MAX_SHM_NAME],
    /// Valid length of `name`.
    name_len: usize,
    /// Logical size set via `ftruncate`.
    size: u64,
    /// Inline data page for small objects.
    data: [u8; 4096],
    /// Owner user ID.
    owner_uid: u32,
    /// Owner group ID.
    owner_gid: u32,
    /// Permission mode bits.
    mode: u16,
    /// Number of open references.
    ref_count: u32,
    /// Marked for deletion but still referenced.
    marked_unlink: bool,
    /// Slot is in use.
    active: bool,
    /// Unique object identifier.
    id: u32,
    /// Creation timestamp (nanoseconds since boot).
    created_ns: u64,
    /// Last modification timestamp (nanoseconds).
    modified_ns: u64,
}

impl ShmObject {
    /// Create a zeroed, inactive object.
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_SHM_NAME],
            name_len: 0,
            size: 0,
            data: [0u8; 4096],
            owner_uid: 0,
            owner_gid: 0,
            mode: 0,
            ref_count: 0,
            marked_unlink: false,
            active: false,
            id: 0,
            created_ns: 0,
            modified_ns: 0,
        }
    }

    /// Check whether the stored name equals `other`.
    fn name_eq(&self, other: &[u8]) -> bool {
        self.name_len == other.len() && self.name[..self.name_len] == *other
    }
}

// -- ShmOpenFlags ----------------------------------------------------

/// Decoded open-flag set for `shm_open`.
#[derive(Debug, Clone, Copy)]
pub struct ShmOpenFlags {
    /// Open read-only (no writes permitted).
    pub read_only: bool,
    /// Create the object if it does not exist.
    pub create: bool,
    /// Fail with `AlreadyExists` when combined with `create`.
    pub exclusive: bool,
    /// Truncate size to zero on open.
    pub truncate: bool,
}

impl ShmOpenFlags {
    /// Decode a raw POSIX flags integer.
    pub fn from_flags(flags: i32) -> Self {
        Self {
            read_only: (flags & _O_RDWR) == 0,
            create: (flags & O_CREAT) != 0,
            exclusive: (flags & O_EXCL) != 0,
            truncate: (flags & O_TRUNC) != 0,
        }
    }
}

// -- ShmStat ---------------------------------------------------------

/// Status information returned by [`ShmRegistry::stat`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ShmStat {
    /// Logical object size.
    pub size: u64,
    /// Owner user ID.
    pub owner_uid: u32,
    /// Owner group ID.
    pub owner_gid: u32,
    /// Permission mode bits.
    pub mode: u16,
    /// Number of open references.
    pub ref_count: u32,
    /// Creation timestamp (nanoseconds).
    pub created_ns: u64,
    /// Last modification timestamp (nanoseconds).
    pub modified_ns: u64,
}

// -- ShmRegistry -----------------------------------------------------

/// System-wide registry of POSIX shared memory objects.
pub struct ShmRegistry {
    /// Fixed-size pool of shared memory objects.
    objects: [ShmObject; MAX_SHM_OBJECTS],
    /// Next unique identifier to assign.
    next_id: u32,
    /// Number of currently active objects.
    count: usize,
}

impl Default for ShmRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ShmRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const EMPTY: ShmObject = ShmObject::empty();
        Self {
            objects: [EMPTY; MAX_SHM_OBJECTS],
            next_id: 1,
            count: 0,
        }
    }

    /// Open or create a POSIX shared memory object.
    ///
    /// Returns the unique object ID on success.
    ///
    /// # Flags
    ///
    /// - `O_CREAT` — create the object if it does not exist.
    /// - `O_CREAT | O_EXCL` — fail with `AlreadyExists` if the
    ///   object already exists.
    /// - `O_TRUNC` — set size to zero on open.
    pub fn shm_open(&mut self, name: &[u8], flags: i32, mode: u16) -> Result<u32> {
        if name.is_empty() || name.len() > MAX_SHM_NAME {
            return Err(Error::InvalidArgument);
        }

        let decoded = ShmOpenFlags::from_flags(flags);

        // Look for an existing object with the same name.
        if let Some(idx) = self.find_index(name) {
            let obj = &mut self.objects[idx];

            if obj.marked_unlink {
                return Err(Error::NotFound);
            }

            if decoded.create && decoded.exclusive {
                return Err(Error::AlreadyExists);
            }

            if decoded.truncate {
                obj.size = 0;
                obj.data = [0u8; 4096];
            }

            obj.ref_count += 1;
            return Ok(obj.id);
        }

        // Object does not exist — must have O_CREAT.
        if !decoded.create {
            return Err(Error::NotFound);
        }

        // Find a free slot.
        let slot = self
            .objects
            .iter()
            .position(|o| !o.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id += 1;

        let obj = &mut self.objects[slot];
        obj.name[..name.len()].copy_from_slice(name);
        obj.name_len = name.len();
        obj.size = 0;
        obj.data = [0u8; 4096];
        obj.owner_uid = 0;
        obj.owner_gid = 0;
        obj.mode = mode;
        obj.ref_count = 1;
        obj.marked_unlink = false;
        obj.active = true;
        obj.id = id;
        obj.created_ns = 0;
        obj.modified_ns = 0;

        self.count += 1;
        Ok(id)
    }

    /// Mark a shared memory object for deletion.
    ///
    /// If the reference count is zero the object is freed
    /// immediately; otherwise it is removed once the last
    /// reference is closed.
    pub fn shm_unlink(&mut self, name: &[u8]) -> Result<()> {
        let idx = self.find_index(name).ok_or(Error::NotFound)?;

        let obj = &mut self.objects[idx];
        if obj.marked_unlink {
            return Err(Error::NotFound);
        }

        if obj.ref_count == 0 {
            self.deactivate(idx);
        } else {
            obj.marked_unlink = true;
        }
        Ok(())
    }

    /// Set the logical size of a shared memory object.
    ///
    /// Only the first 4096 bytes are stored inline; the rest
    /// would be backed by page-allocator pages in a full
    /// implementation.
    pub fn ftruncate(&mut self, id: u32, size: u64) -> Result<()> {
        if size > MAX_SHM_SIZE {
            return Err(Error::InvalidArgument);
        }

        let obj = self.find_by_id_mut(id)?;
        obj.size = size;
        obj.modified_ns = 0; // placeholder timestamp
        Ok(())
    }

    /// Read bytes from a shared memory object.
    ///
    /// Returns the number of bytes actually read (may be less
    /// than `buf.len()` if the read extends past the object size
    /// or beyond the inline page).
    pub fn read(&self, id: u32, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let obj = self.find_by_id(id)?;

        if offset >= obj.size {
            return Ok(0);
        }

        let avail = (obj.size - offset) as usize;
        let inline_end = 4096usize;
        let off = offset as usize;

        if off >= inline_end {
            // Beyond inline page — would need page allocator.
            return Ok(0);
        }

        let can_read = avail.min(buf.len()).min(inline_end.saturating_sub(off));

        buf[..can_read].copy_from_slice(&obj.data[off..off + can_read]);
        Ok(can_read)
    }

    /// Write bytes into a shared memory object.
    ///
    /// Returns the number of bytes actually written.
    pub fn write(&mut self, id: u32, offset: u64, data: &[u8]) -> Result<usize> {
        let obj = self.find_by_id_mut(id)?;

        if offset >= obj.size {
            return Err(Error::InvalidArgument);
        }

        let avail = (obj.size - offset) as usize;
        let inline_end = 4096usize;
        let off = offset as usize;

        if off >= inline_end {
            return Ok(0);
        }

        let can_write = avail.min(data.len()).min(inline_end.saturating_sub(off));

        obj.data[off..off + can_write].copy_from_slice(&data[..can_write]);
        obj.modified_ns = 0; // placeholder timestamp
        Ok(can_write)
    }

    /// Close one reference to a shared memory object.
    ///
    /// If the object was marked for unlinking and the reference
    /// count drops to zero, the slot is freed.
    pub fn close(&mut self, id: u32) -> Result<()> {
        let idx = self.find_idx_by_id(id)?;
        let obj = &mut self.objects[idx];

        if obj.ref_count == 0 {
            return Err(Error::InvalidArgument);
        }

        obj.ref_count -= 1;

        if obj.ref_count == 0 && obj.marked_unlink {
            self.deactivate(idx);
        }

        Ok(())
    }

    /// Retrieve status information for a shared memory object.
    pub fn stat(&self, id: u32) -> Result<ShmStat> {
        let obj = self.find_by_id(id)?;
        Ok(ShmStat {
            size: obj.size,
            owner_uid: obj.owner_uid,
            owner_gid: obj.owner_gid,
            mode: obj.mode,
            ref_count: obj.ref_count,
            created_ns: obj.created_ns,
            modified_ns: obj.modified_ns,
        })
    }

    /// Look up an object by name, returning its ID if found.
    pub fn lookup(&self, name: &[u8]) -> Option<u32> {
        self.objects
            .iter()
            .find(|o| o.active && !o.marked_unlink && o.name_eq(name))
            .map(|o| o.id)
    }

    /// Number of active shared memory objects.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the registry contains no active objects.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    // -- private helpers ---------------------------------------------

    /// Find slot index by name.
    fn find_index(&self, name: &[u8]) -> Option<usize> {
        self.objects
            .iter()
            .position(|o| o.active && o.name_eq(name))
    }

    /// Find slot index by object ID.
    fn find_idx_by_id(&self, id: u32) -> Result<usize> {
        self.objects
            .iter()
            .position(|o| o.active && o.id == id)
            .ok_or(Error::NotFound)
    }

    /// Immutable reference by ID.
    fn find_by_id(&self, id: u32) -> Result<&ShmObject> {
        self.objects
            .iter()
            .find(|o| o.active && o.id == id)
            .ok_or(Error::NotFound)
    }

    /// Mutable reference by ID.
    fn find_by_id_mut(&mut self, id: u32) -> Result<&mut ShmObject> {
        self.objects
            .iter_mut()
            .find(|o| o.active && o.id == id)
            .ok_or(Error::NotFound)
    }

    /// Deactivate a slot and decrement the count.
    fn deactivate(&mut self, idx: usize) {
        self.objects[idx] = ShmObject::empty();
        self.count -= 1;
    }
}
