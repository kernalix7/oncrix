// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `memfd_create` and file sealing syscall handlers.
//!
//! Implements anonymous memory file descriptors with sealing support
//! per Linux `memfd_create(2)` semantics. Memfds are anonymous files
//! backed by RAM that support the `F_ADD_SEALS` / `F_GET_SEALS`
//! `fcntl` operations for immutability guarantees.
//!
//! Reference: `memfd_create(2)`, `fcntl(2)` (sealing operations).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// memfd_create flags
// ---------------------------------------------------------------------------

/// Set close-on-exec on the new file descriptor.
pub const MFD_CLOEXEC: u32 = 0x0001;

/// Allow `F_ADD_SEALS` operations on this memfd.
pub const MFD_ALLOW_SEALING: u32 = 0x0002;

/// Use huge pages for the backing memory.
pub const MFD_HUGETLB: u32 = 0x0004;

/// Mask of all valid `memfd_create` flags.
const MFD_ALL_FLAGS: u32 = MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_HUGETLB;

// ---------------------------------------------------------------------------
// File seal flags (fcntl F_ADD_SEALS / F_GET_SEALS)
// ---------------------------------------------------------------------------

/// Prevent further sealing — no more `F_ADD_SEALS` calls.
pub const F_SEAL_SEAL: u32 = 0x0001;

/// Prevent the file from being shrunk via `ftruncate`.
pub const F_SEAL_SHRINK: u32 = 0x0002;

/// Prevent the file from being grown via `ftruncate` or writes past EOF.
pub const F_SEAL_GROW: u32 = 0x0004;

/// Prevent all writes to the file.
pub const F_SEAL_WRITE: u32 = 0x0008;

/// Prevent future `mmap(PROT_WRITE)` mappings (existing ones stay).
pub const F_SEAL_FUTURE_WRITE: u32 = 0x0010;

/// Mask of all valid seal flags.
const F_SEAL_ALL: u32 =
    F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of concurrent memfd objects.
const MAX_MEMFDS: usize = 64;

/// Maximum length of a memfd name (bytes, excluding NUL).
const MAX_NAME_LEN: usize = 250;

/// Inline data capacity per memfd (bytes).
const INLINE_CAPACITY: usize = 8192;

// ---------------------------------------------------------------------------
// Memfd — a single anonymous memory file
// ---------------------------------------------------------------------------

/// A single anonymous memory file descriptor with sealing support.
pub struct Memfd {
    /// Unique identifier for this memfd.
    id: u64,
    /// Name bytes (debug/display only, per `memfd_create` semantics).
    name: [u8; MAX_NAME_LEN],
    /// Valid length of `name`.
    name_len: usize,
    /// Creation flags (`MFD_*`).
    flags: u32,
    /// Active seals bitmask (`F_SEAL_*`).
    seals: u32,
    /// Inline data buffer.
    data: [u8; INLINE_CAPACITY],
    /// Logical file size.
    size: u64,
    /// Allocated capacity (always [`INLINE_CAPACITY`] for now).
    capacity: u64,
    /// PID of the creating process.
    owner_pid: u64,
    /// Whether this slot is in use.
    in_use: bool,
}

impl Memfd {
    /// Create an empty, inactive memfd slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            flags: 0,
            seals: 0,
            data: [0u8; INLINE_CAPACITY],
            size: 0,
            capacity: INLINE_CAPACITY as u64,
            owner_pid: 0,
            in_use: false,
        }
    }

    /// Write `src` bytes at `offset` into this memfd.
    ///
    /// Returns the number of bytes actually written.
    /// Fails if `F_SEAL_WRITE` is active or if growing is sealed.
    pub fn write(&mut self, offset: u64, src: &[u8]) -> Result<usize> {
        if self.seals & F_SEAL_WRITE != 0 {
            return Err(Error::PermissionDenied);
        }

        let off = offset as usize;
        let cap = self.capacity as usize;

        // Check if write would grow the file.
        let end = off.saturating_add(src.len());
        if end as u64 > self.size && self.seals & F_SEAL_GROW != 0 {
            return Err(Error::PermissionDenied);
        }

        if off >= cap {
            return Ok(0);
        }

        let can_write = src.len().min(cap.saturating_sub(off));
        self.data[off..off + can_write].copy_from_slice(&src[..can_write]);

        // Extend logical size if the write went past current EOF.
        let new_end = (off + can_write) as u64;
        if new_end > self.size {
            self.size = new_end;
        }

        Ok(can_write)
    }

    /// Read bytes from `offset` into `buf`.
    ///
    /// Returns the number of bytes actually read.
    pub fn read(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= self.size {
            return Ok(0);
        }

        let off = offset as usize;
        if off >= INLINE_CAPACITY {
            return Ok(0);
        }

        let avail = (self.size - offset) as usize;
        let can_read = avail
            .min(buf.len())
            .min(INLINE_CAPACITY.saturating_sub(off));

        buf[..can_read].copy_from_slice(&self.data[off..off + can_read]);
        Ok(can_read)
    }

    /// Truncate (or extend) the file to `new_size`.
    ///
    /// Respects `F_SEAL_SHRINK` and `F_SEAL_GROW`.
    pub fn truncate(&mut self, new_size: u64) -> Result<()> {
        if new_size < self.size && self.seals & F_SEAL_SHRINK != 0 {
            return Err(Error::PermissionDenied);
        }
        if new_size > self.size && self.seals & F_SEAL_GROW != 0 {
            return Err(Error::PermissionDenied);
        }

        // Zero out bytes between new size and old size when shrinking.
        if new_size < self.size {
            let start = (new_size as usize).min(INLINE_CAPACITY);
            let end = (self.size as usize).min(INLINE_CAPACITY);
            if start < end {
                self.data[start..end].fill(0);
            }
        }

        self.size = new_size;
        Ok(())
    }

    /// Add a seal to this memfd.
    ///
    /// Fails if `MFD_ALLOW_SEALING` was not set at creation time,
    /// or if `F_SEAL_SEAL` is already active (no further sealing).
    pub fn add_seal(&mut self, seal: u32) -> Result<()> {
        if self.flags & MFD_ALLOW_SEALING == 0 {
            return Err(Error::PermissionDenied);
        }
        if self.seals & F_SEAL_SEAL != 0 {
            return Err(Error::PermissionDenied);
        }
        if seal & !F_SEAL_ALL != 0 {
            return Err(Error::InvalidArgument);
        }

        self.seals |= seal;
        Ok(())
    }

    /// Return the current seals bitmask.
    pub fn get_seals(&self) -> u32 {
        self.seals
    }
}

// ---------------------------------------------------------------------------
// MemfdRegistry — system-wide table of memfd objects
// ---------------------------------------------------------------------------

/// System-wide registry of anonymous memory file descriptors.
pub struct MemfdRegistry {
    /// Fixed-size pool of memfd slots.
    fds: [Memfd; MAX_MEMFDS],
    /// Number of active memfd objects.
    count: usize,
    /// Next unique identifier to assign.
    next_id: u64,
}

impl Default for MemfdRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MemfdRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const EMPTY: Memfd = Memfd::empty();
        Self {
            fds: [EMPTY; MAX_MEMFDS],
            count: 0,
            next_id: 1,
        }
    }

    /// Create a new anonymous memory file.
    ///
    /// Returns the unique memfd identifier on success.
    pub fn memfd_create(&mut self, name: &[u8], flags: u32, pid: u64) -> Result<u64> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if flags & !MFD_ALL_FLAGS != 0 {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .fds
            .iter()
            .position(|fd| !fd.in_use)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id += 1;

        let fd = &mut self.fds[slot];
        *fd = Memfd::empty();
        fd.id = id;
        fd.name[..name.len()].copy_from_slice(name);
        fd.name_len = name.len();
        fd.flags = flags;
        fd.owner_pid = pid;
        fd.in_use = true;

        self.count += 1;
        Ok(id)
    }

    /// Write data to a memfd at the given offset.
    pub fn memfd_write(&mut self, id: u64, offset: u64, data: &[u8]) -> Result<usize> {
        self.find_mut(id)?.write(offset, data)
    }

    /// Read data from a memfd at the given offset.
    pub fn memfd_read(&self, id: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.get(id)?.read(offset, buf)
    }

    /// Truncate a memfd to the given size.
    pub fn memfd_truncate(&mut self, id: u64, size: u64) -> Result<()> {
        self.find_mut(id)?.truncate(size)
    }

    /// Add seals to a memfd.
    pub fn memfd_add_seal(&mut self, id: u64, seal: u32) -> Result<()> {
        self.find_mut(id)?.add_seal(seal)
    }

    /// Get the current seals of a memfd.
    pub fn memfd_get_seals(&self, id: u64) -> Result<u32> {
        Ok(self.get(id)?.get_seals())
    }

    /// Close (destroy) a memfd.
    pub fn memfd_close(&mut self, id: u64) -> Result<()> {
        let idx = self
            .fds
            .iter()
            .position(|fd| fd.in_use && fd.id == id)
            .ok_or(Error::NotFound)?;

        self.fds[idx] = Memfd::empty();
        self.count -= 1;
        Ok(())
    }

    /// Get an immutable reference to a memfd by its identifier.
    pub fn get(&self, id: u64) -> Result<&Memfd> {
        self.fds
            .iter()
            .find(|fd| fd.in_use && fd.id == id)
            .ok_or(Error::NotFound)
    }

    /// Number of active memfd objects.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the registry contains no active memfd objects.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    // -- private helpers -------------------------------------------------

    /// Mutable reference to a memfd by its identifier.
    fn find_mut(&mut self, id: u64) -> Result<&mut Memfd> {
        self.fds
            .iter_mut()
            .find(|fd| fd.in_use && fd.id == id)
            .ok_or(Error::NotFound)
    }
}

// ---------------------------------------------------------------------------
// Syscall handler functions
// ---------------------------------------------------------------------------

/// `memfd_create` — create an anonymous memory file descriptor.
///
/// Creates a new anonymous file backed by RAM. The `name` is used
/// for debugging only (visible in `/proc/self/fd/`). Returns the
/// memfd identifier on success.
///
/// # Flags
///
/// - [`MFD_CLOEXEC`] — set close-on-exec on the descriptor.
/// - [`MFD_ALLOW_SEALING`] — allow `F_ADD_SEALS` operations.
/// - [`MFD_HUGETLB`] — use huge pages for backing memory.
pub fn do_memfd_create(name: &[u8], flags: u32, pid: u64) -> Result<u64> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(Error::InvalidArgument);
    }
    if flags & !MFD_ALL_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }

    // Stub: a real implementation would allocate via the global
    // MemfdRegistry and return the file descriptor number.
    let _ = pid;
    Err(Error::NotImplemented)
}

/// `fcntl(fd, F_ADD_SEALS, seals)` — add seals to a memfd.
///
/// Requires that the memfd was created with [`MFD_ALLOW_SEALING`].
/// Once [`F_SEAL_SEAL`] is set, no further seals may be added.
pub fn do_fcntl_add_seals(fd: u64, seals: u32) -> Result<()> {
    if seals & !F_SEAL_ALL != 0 {
        return Err(Error::InvalidArgument);
    }

    let _ = fd;

    // Stub: a real implementation would look up the fd in the
    // process file table and call `Memfd::add_seal`.
    Err(Error::NotImplemented)
}

/// `fcntl(fd, F_GET_SEALS)` — retrieve current seals of a memfd.
pub fn do_fcntl_get_seals(fd: u64) -> Result<u32> {
    let _ = fd;

    // Stub: a real implementation would look up the fd in the
    // process file table and call `Memfd::get_seals`.
    Err(Error::NotImplemented)
}
