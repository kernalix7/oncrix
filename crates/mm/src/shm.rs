// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared memory and `memfd_create` support.
//!
//! Provides anonymous shared memory segments that can be passed
//! between processes via file descriptors. Each segment stores
//! data inline (no heap allocation) with a fixed 64 KiB capacity.
//!
//! # Features
//!
//! - `memfd_create`-compatible anonymous memory objects
//! - File sealing (`F_SEAL_*`) for immutability guarantees
//! - Read/write/truncate operations with seal enforcement
//! - Registry for managing up to 32 concurrent segments
//!
//! # POSIX Reference
//!
//! See `memfd_create(2)` (Linux-specific) and `shm_open(3)` (POSIX).
//! File sealing is described in `fcntl(2)` under `F_ADD_SEALS`.

use oncrix_lib::{Error, Result};

// ── memfd_create flags ─────────────────────────────────────────

/// Set close-on-exec (`FD_CLOEXEC`) on the new file descriptor.
pub const MFD_CLOEXEC: u32 = 0x1;

/// Allow `F_ADD_SEALS` / `F_GET_SEALS` operations on this fd.
pub const MFD_ALLOW_SEALING: u32 = 0x2;

/// Bitmask of all valid `memfd_create` flags.
const MFD_VALID_FLAGS: u32 = MFD_CLOEXEC | MFD_ALLOW_SEALING;

// ── File seal flags ────────────────────────────────────────────

/// Seal-related flag constants for `fcntl(F_ADD_SEALS)`.
pub mod seal_flags {
    /// Prevent further seal operations (`F_ADD_SEALS` will fail).
    pub const F_SEAL_SEAL: u32 = 0x1;
    /// Prevent the file from being shrunk via `ftruncate`.
    pub const F_SEAL_SHRINK: u32 = 0x2;
    /// Prevent the file from being grown via `ftruncate` or `write`.
    pub const F_SEAL_GROW: u32 = 0x4;
    /// Prevent all write operations (makes the mapping immutable).
    pub const F_SEAL_WRITE: u32 = 0x8;
    /// Allow existing writable mappings but prevent new ones.
    pub const F_SEAL_FUTURE_WRITE: u32 = 0x10;

    /// Bitmask of all valid seal flags.
    pub const VALID_SEALS: u32 =
        F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE;
}

// ── Capacity constants ─────────────────────────────────────────

/// Maximum name length for a shared memory segment (bytes).
const SHM_NAME_MAX: usize = 64;

/// Maximum data capacity per segment (64 KiB).
const SHM_DATA_CAPACITY: usize = 65536;

/// Maximum number of segments in the global registry.
const SHM_MAX_SEGMENTS: usize = 32;

// ── ShmSegment ─────────────────────────────────────────────────

/// A single shared memory segment backed by inline storage.
///
/// Data is stored in a fixed `[u8; 65536]` array (64 KiB) with no
/// heap allocation, making this safe for `#![no_std]` kernel use.
///
/// The segment supports POSIX-like read, write, truncate, and file
/// sealing operations.
pub struct ShmSegment {
    /// Segment name (e.g., `memfd:foo`), stored inline.
    name: [u8; SHM_NAME_MAX],
    /// Number of valid bytes in `name`.
    name_len: usize,
    /// Inline data buffer.
    data: [u8; SHM_DATA_CAPACITY],
    /// Current logical size (bytes written / set by truncate).
    size: usize,
    /// Maximum capacity (always `SHM_DATA_CAPACITY`).
    capacity: usize,
    /// `memfd_create` flags (`MFD_CLOEXEC`, `MFD_ALLOW_SEALING`).
    flags: u32,
    /// Active seal bitmask (see [`seal_flags`]).
    sealed: u32,
    /// Whether this slot is occupied in the registry.
    in_use: bool,
}

impl ShmSegment {
    /// Create a new shared memory segment with the given name and flags.
    ///
    /// The name is truncated to [`SHM_NAME_MAX`] bytes if longer.
    /// Valid flags are [`MFD_CLOEXEC`] and [`MFD_ALLOW_SEALING`].
    ///
    /// The segment starts with size 0 and no seals applied.
    pub fn new(name: &str, flags: u32) -> Self {
        let mut seg = Self {
            name: [0u8; SHM_NAME_MAX],
            name_len: 0,
            data: [0u8; SHM_DATA_CAPACITY],
            size: 0,
            capacity: SHM_DATA_CAPACITY,
            flags: flags & MFD_VALID_FLAGS,
            sealed: 0,
            in_use: true,
        };

        let bytes = name.as_bytes();
        let copy_len = if bytes.len() < SHM_NAME_MAX {
            bytes.len()
        } else {
            SHM_NAME_MAX
        };

        let mut i = 0;
        while i < copy_len {
            seg.name[i] = bytes[i];
            i += 1;
        }
        seg.name_len = copy_len;

        seg
    }

    /// Return an empty, unused segment (for registry initialization).
    const fn empty() -> Self {
        Self {
            name: [0u8; SHM_NAME_MAX],
            name_len: 0,
            data: [0u8; SHM_DATA_CAPACITY],
            size: 0,
            capacity: SHM_DATA_CAPACITY,
            flags: 0,
            sealed: 0,
            in_use: false,
        }
    }

    /// Read data from the segment at the given byte offset.
    ///
    /// Copies up to `buf.len()` bytes from `[offset..]` into `buf`.
    /// Returns the number of bytes actually read (may be less than
    /// `buf.len()` if `offset + buf.len()` exceeds the segment size).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `offset` is beyond `size`.
    pub fn read(&self, offset: usize, buf: &mut [u8]) -> Result<usize> {
        if offset > self.size {
            return Err(Error::InvalidArgument);
        }

        let available = self.size.saturating_sub(offset);
        let copy_len = if buf.len() < available {
            buf.len()
        } else {
            available
        };

        let mut i = 0;
        while i < copy_len {
            buf[i] = self.data[offset.saturating_add(i)];
            i += 1;
        }

        Ok(copy_len)
    }

    /// Write data into the segment at the given byte offset.
    ///
    /// If the write extends beyond the current `size`, the size is
    /// grown accordingly (up to `capacity`).
    ///
    /// # Errors
    ///
    /// - [`Error::PermissionDenied`] if `F_SEAL_WRITE` is active.
    /// - [`Error::PermissionDenied`] if `F_SEAL_GROW` is active and
    ///   the write would extend beyond the current size.
    /// - [`Error::InvalidArgument`] if `offset` exceeds capacity.
    /// - [`Error::OutOfMemory`] if the write would exceed capacity.
    pub fn write(&mut self, offset: usize, data: &[u8]) -> Result<usize> {
        // F_SEAL_WRITE forbids all writes.
        if self.sealed & seal_flags::F_SEAL_WRITE != 0 {
            return Err(Error::PermissionDenied);
        }

        if offset > self.capacity {
            return Err(Error::InvalidArgument);
        }

        let end = offset.saturating_add(data.len());
        if end > self.capacity {
            return Err(Error::OutOfMemory);
        }

        // F_SEAL_GROW forbids extending beyond current size.
        if self.sealed & seal_flags::F_SEAL_GROW != 0 && end > self.size {
            return Err(Error::PermissionDenied);
        }

        let copy_len = data.len();
        let mut i = 0;
        while i < copy_len {
            self.data[offset.saturating_add(i)] = data[i];
            i += 1;
        }

        // Grow size if the write extends past it.
        if end > self.size {
            self.size = end;
        }

        Ok(copy_len)
    }

    /// Set the logical size of the segment (analogous to `ftruncate`).
    ///
    /// If `new_size` is smaller than the current size, the trailing
    /// bytes are zeroed. If larger, the gap is zero-filled.
    ///
    /// # Errors
    ///
    /// - [`Error::PermissionDenied`] if `F_SEAL_SHRINK` is active and
    ///   `new_size < self.size`.
    /// - [`Error::PermissionDenied`] if `F_SEAL_GROW` is active and
    ///   `new_size > self.size`.
    /// - [`Error::OutOfMemory`] if `new_size` exceeds `capacity`.
    pub fn truncate(&mut self, new_size: usize) -> Result<()> {
        if new_size > self.capacity {
            return Err(Error::OutOfMemory);
        }

        if new_size < self.size && self.sealed & seal_flags::F_SEAL_SHRINK != 0 {
            return Err(Error::PermissionDenied);
        }

        if new_size > self.size && self.sealed & seal_flags::F_SEAL_GROW != 0 {
            return Err(Error::PermissionDenied);
        }

        // Zero the region between old and new size (both directions).
        if new_size < self.size {
            let mut i = new_size;
            while i < self.size {
                self.data[i] = 0;
                i += 1;
            }
        }
        // Growing: the gap is already zero from initialization or
        // a previous truncate that zeroed it.

        self.size = new_size;
        Ok(())
    }

    /// Add seal flags to this segment.
    ///
    /// Seals are additive and cannot be removed once set.
    ///
    /// # Errors
    ///
    /// - [`Error::PermissionDenied`] if `MFD_ALLOW_SEALING` was not
    ///   set at creation time.
    /// - [`Error::PermissionDenied`] if `F_SEAL_SEAL` is already
    ///   active (no further seals can be added).
    /// - [`Error::InvalidArgument`] if `seals` contains unknown bits.
    pub fn add_seals(&mut self, seals: u32) -> Result<()> {
        // Sealing must have been allowed at creation time.
        if self.flags & MFD_ALLOW_SEALING == 0 {
            return Err(Error::PermissionDenied);
        }

        // F_SEAL_SEAL prevents adding any more seals.
        if self.sealed & seal_flags::F_SEAL_SEAL != 0 {
            return Err(Error::PermissionDenied);
        }

        // Reject unknown seal bits.
        if seals & !seal_flags::VALID_SEALS != 0 {
            return Err(Error::InvalidArgument);
        }

        self.sealed |= seals;
        Ok(())
    }

    /// Return the current seal bitmask.
    pub fn get_seals(&self) -> u32 {
        self.sealed
    }

    /// Return the current logical size of the segment.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Return the maximum capacity of the segment.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Return the creation flags.
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// Return the segment name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return whether this segment slot is in use.
    pub fn in_use(&self) -> bool {
        self.in_use
    }
}

// ── ShmRegistry ────────────────────────────────────────────────

/// Registry that manages up to [`SHM_MAX_SEGMENTS`] shared memory
/// segments.
///
/// Segments are addressed by index (0..31). The registry provides
/// create, lookup, close, and name-search operations.
pub struct ShmRegistry {
    /// Fixed-size array of segment slots.
    segments: [ShmSegment; SHM_MAX_SEGMENTS],
}

impl Default for ShmRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ShmRegistry {
    /// Create a new, empty registry.
    pub const fn new() -> Self {
        Self {
            segments: [const { ShmSegment::empty() }; SHM_MAX_SEGMENTS],
        }
    }

    /// Create a new shared memory segment.
    ///
    /// Finds the first free slot, initializes it with the given name
    /// and flags, and returns the slot index.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if all 32 slots are occupied.
    /// - [`Error::InvalidArgument`] if `name` is empty or `flags`
    ///   contains unknown bits.
    pub fn create(&mut self, name: &str, flags: u32) -> Result<usize> {
        if name.is_empty() {
            return Err(Error::InvalidArgument);
        }
        if flags & !MFD_VALID_FLAGS != 0 {
            return Err(Error::InvalidArgument);
        }

        // Find a free slot.
        let mut idx = 0;
        while idx < SHM_MAX_SEGMENTS {
            if !self.segments[idx].in_use {
                self.segments[idx] = ShmSegment::new(name, flags);
                return Ok(idx);
            }
            idx += 1;
        }

        Err(Error::OutOfMemory)
    }

    /// Get an immutable reference to a segment by index.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `index` is out of range.
    /// - [`Error::NotFound`] if the slot is not in use.
    pub fn get(&self, index: usize) -> Result<&ShmSegment> {
        if index >= SHM_MAX_SEGMENTS {
            return Err(Error::InvalidArgument);
        }
        if !self.segments[index].in_use {
            return Err(Error::NotFound);
        }
        Ok(&self.segments[index])
    }

    /// Get a mutable reference to a segment by index.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `index` is out of range.
    /// - [`Error::NotFound`] if the slot is not in use.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut ShmSegment> {
        if index >= SHM_MAX_SEGMENTS {
            return Err(Error::InvalidArgument);
        }
        if !self.segments[index].in_use {
            return Err(Error::NotFound);
        }
        Ok(&mut self.segments[index])
    }

    /// Close (release) a segment by index.
    ///
    /// The slot is marked as unused and its data is zeroed.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `index` is out of range.
    /// - [`Error::NotFound`] if the slot is not in use.
    pub fn close(&mut self, index: usize) -> Result<()> {
        if index >= SHM_MAX_SEGMENTS {
            return Err(Error::InvalidArgument);
        }
        if !self.segments[index].in_use {
            return Err(Error::NotFound);
        }
        self.segments[index] = ShmSegment::empty();
        Ok(())
    }

    /// Find the first segment whose name matches `name`.
    ///
    /// Returns the slot index, or `None` if no match is found.
    pub fn find_by_name(&self, name: &str) -> Option<usize> {
        let target = name.as_bytes();
        let mut idx = 0;
        while idx < SHM_MAX_SEGMENTS {
            let seg = &self.segments[idx];
            if seg.in_use && seg.name_len == target.len() {
                let mut matched = true;
                let mut j = 0;
                while j < target.len() {
                    if seg.name[j] != target[j] {
                        matched = false;
                        break;
                    }
                    j += 1;
                }
                if matched {
                    return Some(idx);
                }
            }
            idx += 1;
        }
        None
    }

    /// Return the number of segments currently in use.
    pub fn count(&self) -> usize {
        let mut n = 0;
        let mut idx = 0;
        while idx < SHM_MAX_SEGMENTS {
            if self.segments[idx].in_use {
                n += 1;
            }
            idx += 1;
        }
        n
    }
}
