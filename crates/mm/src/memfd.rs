// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `memfd_create` implementation -- anonymous memory file descriptors.
//!
//! Provides anonymous files backed by memory with optional file sealing
//! for safe, zero-copy sharing between processes. Unlike `shm_open`,
//! `memfd_create` does not require a name in the filesystem namespace;
//! the file descriptor is the only handle to the memory.
//!
//! # Architecture
//!
//! - [`MemfdFlags`] -- creation flags (`MFD_CLOEXEC`, `MFD_ALLOW_SEALING`,
//!   `MFD_HUGETLB`)
//! - [`SealFlags`] -- file seal bits (`F_SEAL_SEAL`, `F_SEAL_SHRINK`,
//!   `F_SEAL_GROW`, `F_SEAL_WRITE`, `F_SEAL_FUTURE_WRITE`)
//! - [`MemfdState`] -- lifecycle state of a memfd
//! - [`MemfdFile`] -- per-fd state (owner, size, seals, data)
//! - [`MemfdStats`] -- aggregate statistics
//! - [`MemfdManager`] -- system-wide registry of memfd instances
//!
//! # File Sealing
//!
//! Once `MFD_ALLOW_SEALING` is set at creation time, the owner can
//! progressively add seals to restrict future operations:
//!
//! - `F_SEAL_SEAL` -- no further seals may be added
//! - `F_SEAL_SHRINK` -- size cannot decrease
//! - `F_SEAL_GROW` -- size cannot increase
//! - `F_SEAL_WRITE` -- content is immutable (enables safe zero-copy)
//! - `F_SEAL_FUTURE_WRITE` -- new writable mappings are forbidden
//!
//! Seals are monotonic (once set, never cleared) and are enforced on
//! every write, truncate, and mmap operation.
//!
//! # POSIX Reference
//!
//! `memfd_create(2)` (Linux-specific), `fcntl(2)` `F_ADD_SEALS` /
//! `F_GET_SEALS`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Maximum number of memfd instances system-wide.
const MAX_MEMFDS: usize = 128;

/// Maximum inline data capacity per memfd (64 KiB).
///
/// In a real kernel the backing store would be page-cache pages; here
/// we use a fixed inline buffer for `no_std` compatibility.
const MAX_MEMFD_DATA: usize = 64 * 1024;

/// Maximum name length in bytes (including terminating NUL in Linux,
/// but we store only the valid bytes).
const MAX_MEMFD_NAME_LEN: usize = 249;

/// Starting fd number for memfd instances.
const MEMFD_FD_BASE: u32 = 2000;

/// Maximum number of mapping records per memfd.
const MAX_MAPPINGS_PER_FD: usize = 16;

// -------------------------------------------------------------------
// MemfdFlags
// -------------------------------------------------------------------

/// Creation flags for `memfd_create`.
pub mod memfd_flags {
    /// Set close-on-exec on the new file descriptor.
    pub const MFD_CLOEXEC: u32 = 1 << 0;

    /// Allow adding file seals via `F_ADD_SEALS`.
    pub const MFD_ALLOW_SEALING: u32 = 1 << 1;

    /// Use huge pages for the backing store.
    pub const MFD_HUGETLB: u32 = 1 << 2;

    /// Mask for the huge-page size encoding (bits 26..31 in Linux;
    /// simplified here).
    pub const MFD_HUGE_MASK: u32 = 0x3F << 26;

    /// All valid flags (excluding huge-page size bits).
    pub const VALID_MASK: u32 = MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_HUGETLB;
}

// -------------------------------------------------------------------
// SealFlags
// -------------------------------------------------------------------

/// File seal bits for `fcntl(F_ADD_SEALS)`.
pub mod seal_flags {
    /// No further seals may be added.
    pub const F_SEAL_SEAL: u32 = 1 << 0;
    /// File size cannot decrease.
    pub const F_SEAL_SHRINK: u32 = 1 << 1;
    /// File size cannot increase.
    pub const F_SEAL_GROW: u32 = 1 << 2;
    /// Content may not be modified (enables zero-copy sharing).
    pub const F_SEAL_WRITE: u32 = 1 << 3;
    /// New writable mappings are forbidden, but existing ones may
    /// continue writing.
    pub const F_SEAL_FUTURE_WRITE: u32 = 1 << 4;

    /// All valid seal bits.
    pub const VALID_MASK: u32 =
        F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE;
}

// -------------------------------------------------------------------
// MemfdState
// -------------------------------------------------------------------

/// Lifecycle state of a memfd instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MemfdState {
    /// Slot is unused.
    #[default]
    Inactive,
    /// Fd is open and ready for use.
    Open,
    /// Fd has active mappings in user space.
    Mapped,
    /// Fd is being closed; cleanup in progress.
    Closing,
}

// -------------------------------------------------------------------
// MappingRecord
// -------------------------------------------------------------------

/// A record of an active memory mapping for a memfd.
#[derive(Debug, Clone, Copy)]
pub struct MappingRecord {
    /// PID of the process that created the mapping.
    pub pid: u64,
    /// Virtual address of the mapping in the process.
    pub virt_addr: u64,
    /// Size of the mapping in bytes.
    pub size: usize,
    /// Whether the mapping is writable.
    pub writable: bool,
    /// Whether this record is active.
    pub active: bool,
}

impl MappingRecord {
    /// Creates an empty, inactive mapping record.
    const fn empty() -> Self {
        Self {
            pid: 0,
            virt_addr: 0,
            size: 0,
            writable: false,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// MemfdFile
// -------------------------------------------------------------------

/// Per-instance state for a `memfd_create` file descriptor.
///
/// Tracks the owner, size, seals, inline data, and active mappings.
pub struct MemfdFile {
    /// Assigned fd number.
    fd: u32,
    /// Owning process PID.
    owner_pid: u64,
    /// Human-readable name.
    name: [u8; MAX_MEMFD_NAME_LEN],
    /// Valid length of `name`.
    name_len: usize,
    /// Creation flags.
    flags: u32,
    /// Active file seals.
    seals: u32,
    /// Current state.
    state: MemfdState,
    /// Current file size in bytes.
    size: usize,
    /// Inline data buffer.
    data: [u8; MAX_MEMFD_DATA],
    /// Active mappings.
    mappings: [MappingRecord; MAX_MAPPINGS_PER_FD],
    /// Number of active mappings.
    mapping_count: usize,
    /// Reference count (number of open fd duplicates).
    ref_count: u32,
    /// Number of write operations performed.
    write_count: u64,
    /// Number of read operations performed.
    read_count: u64,
}

impl MemfdFile {
    /// Creates an empty, inactive memfd slot.
    const fn empty() -> Self {
        Self {
            fd: 0,
            owner_pid: 0,
            name: [0u8; MAX_MEMFD_NAME_LEN],
            name_len: 0,
            flags: 0,
            seals: 0,
            state: MemfdState::Inactive,
            size: 0,
            data: [0u8; MAX_MEMFD_DATA],
            mappings: [const { MappingRecord::empty() }; MAX_MAPPINGS_PER_FD],
            mapping_count: 0,
            ref_count: 0,
            write_count: 0,
            read_count: 0,
        }
    }

    /// Returns `true` if this slot is inactive.
    pub const fn is_inactive(&self) -> bool {
        matches!(self.state, MemfdState::Inactive)
    }

    /// Returns the fd number.
    pub const fn fd(&self) -> u32 {
        self.fd
    }

    /// Returns the owning process PID.
    pub const fn owner_pid(&self) -> u64 {
        self.owner_pid
    }

    /// Returns the name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns the creation flags.
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Returns the active seals.
    pub const fn seals(&self) -> u32 {
        self.seals
    }

    /// Returns the current state.
    pub const fn state(&self) -> MemfdState {
        self.state
    }

    /// Returns the current file size.
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Returns the reference count.
    pub const fn ref_count(&self) -> u32 {
        self.ref_count
    }

    /// Returns `true` if sealing is allowed on this memfd.
    pub const fn sealing_allowed(&self) -> bool {
        self.flags & memfd_flags::MFD_ALLOW_SEALING != 0
    }

    /// Checks whether a specific seal is set.
    pub const fn has_seal(&self, seal: u32) -> bool {
        self.seals & seal != 0
    }

    /// Returns the number of active mappings.
    pub const fn mapping_count(&self) -> usize {
        self.mapping_count
    }

    /// Returns a slice of the stored data up to `size`.
    pub fn data(&self) -> &[u8] {
        &self.data[..self.size]
    }
}

// -------------------------------------------------------------------
// MemfdStats
// -------------------------------------------------------------------

/// Aggregate statistics for the memfd subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemfdStats {
    /// Number of active memfd instances.
    pub active_fds: usize,
    /// Total bytes stored across all memfds.
    pub total_bytes: u64,
    /// Total number of active mappings.
    pub total_mappings: usize,
    /// Cumulative `memfd_create` calls.
    pub create_count: u64,
    /// Cumulative close/destroy operations.
    pub destroy_count: u64,
    /// Cumulative seal operations.
    pub seal_count: u64,
    /// Cumulative resize operations.
    pub resize_count: u64,
    /// Cumulative write operations.
    pub write_count: u64,
    /// Cumulative read operations.
    pub read_count: u64,
}

// -------------------------------------------------------------------
// MemfdManager
// -------------------------------------------------------------------

/// System-wide registry of memfd instances.
///
/// Manages creation, sealing, resize, read/write, mapping, and
/// destruction of anonymous memory file descriptors.
pub struct MemfdManager {
    /// Memfd slots.
    files: [MemfdFile; MAX_MEMFDS],
    /// Number of active memfds.
    active_count: usize,
    /// Next fd number to assign.
    next_fd: u32,
    /// Aggregate statistics.
    stats: MemfdStats,
}

impl Default for MemfdManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MemfdManager {
    /// Creates a new, empty memfd manager.
    pub fn new() -> Self {
        Self {
            files: [const { MemfdFile::empty() }; MAX_MEMFDS],
            active_count: 0,
            next_fd: MEMFD_FD_BASE,
            stats: MemfdStats::default(),
        }
    }

    // ---------------------------------------------------------------
    // Lifecycle: create
    // ---------------------------------------------------------------

    /// Creates a new memfd instance (`memfd_create` equivalent).
    ///
    /// Returns the assigned fd number.
    ///
    /// # Arguments
    ///
    /// - `name` -- human-readable name (truncated to 249 bytes)
    /// - `flags` -- creation flags (see [`memfd_flags`])
    /// - `owner_pid` -- PID of the creating process
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `flags` contains unknown bits
    ///   or `name` is empty.
    /// - [`Error::OutOfMemory`] if all slots are occupied.
    pub fn create(&mut self, name: &[u8], flags: u32, owner_pid: u64) -> Result<u32> {
        if name.is_empty() {
            return Err(Error::InvalidArgument);
        }
        if flags & !memfd_flags::VALID_MASK != 0 {
            return Err(Error::InvalidArgument);
        }

        let slot_idx = self.find_free_slot().ok_or(Error::OutOfMemory)?;
        let fd = self.next_fd;
        self.next_fd = self.next_fd.wrapping_add(1);

        let file = &mut self.files[slot_idx];
        *file = MemfdFile::empty();
        file.fd = fd;
        file.owner_pid = owner_pid;
        file.flags = flags;
        file.state = MemfdState::Open;
        file.ref_count = 1;

        let copy_len = name.len().min(MAX_MEMFD_NAME_LEN);
        file.name[..copy_len].copy_from_slice(&name[..copy_len]);
        file.name_len = copy_len;

        self.active_count += 1;
        self.stats.active_fds = self.active_count;
        self.stats.create_count += 1;

        Ok(fd)
    }

    // ---------------------------------------------------------------
    // Sealing
    // ---------------------------------------------------------------

    /// Adds seals to a memfd (`fcntl(F_ADD_SEALS)` equivalent).
    ///
    /// Seals are additive and irreversible. If `F_SEAL_SEAL` is
    /// already set, no further seals may be added.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `fd` is not registered.
    /// - [`Error::PermissionDenied`] if sealing is not allowed on
    ///   this memfd, or `F_SEAL_SEAL` is already set.
    /// - [`Error::InvalidArgument`] if `new_seals` contains invalid
    ///   bits.
    pub fn add_seals(&mut self, fd: u32, new_seals: u32) -> Result<()> {
        if new_seals & !seal_flags::VALID_MASK != 0 {
            return Err(Error::InvalidArgument);
        }

        let idx = self.find_fd_index(fd)?;
        let file = &self.files[idx];

        if !file.sealing_allowed() {
            return Err(Error::PermissionDenied);
        }
        if file.has_seal(seal_flags::F_SEAL_SEAL) {
            return Err(Error::PermissionDenied);
        }

        // If adding F_SEAL_WRITE, check that no writable mappings
        // exist.
        if new_seals & seal_flags::F_SEAL_WRITE != 0 {
            for mapping in &self.files[idx].mappings {
                if mapping.active && mapping.writable {
                    return Err(Error::Busy);
                }
            }
        }

        self.files[idx].seals |= new_seals;
        self.stats.seal_count += 1;

        Ok(())
    }

    /// Returns the current seals on a memfd.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `fd` is not registered.
    pub fn get_seals(&self, fd: u32) -> Result<u32> {
        let idx = self.find_fd_index(fd)?;
        Ok(self.files[idx].seals)
    }

    // ---------------------------------------------------------------
    // Resize (ftruncate equivalent)
    // ---------------------------------------------------------------

    /// Resizes a memfd (analogous to `ftruncate`).
    ///
    /// Enforces `F_SEAL_SHRINK` and `F_SEAL_GROW` seals. New bytes
    /// beyond the old size are zero-filled. The size must not exceed
    /// [`MAX_MEMFD_DATA`].
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `fd` is not registered.
    /// - [`Error::PermissionDenied`] if a shrink/grow seal prevents
    ///   the operation.
    /// - [`Error::InvalidArgument`] if `new_size` exceeds capacity.
    pub fn resize(&mut self, fd: u32, new_size: usize) -> Result<()> {
        if new_size > MAX_MEMFD_DATA {
            return Err(Error::InvalidArgument);
        }

        let idx = self.find_fd_index(fd)?;
        let old_size = self.files[idx].size;

        if new_size < old_size && self.files[idx].has_seal(seal_flags::F_SEAL_SHRINK) {
            return Err(Error::PermissionDenied);
        }
        if new_size > old_size && self.files[idx].has_seal(seal_flags::F_SEAL_GROW) {
            return Err(Error::PermissionDenied);
        }

        if new_size > old_size {
            // Zero-fill the extension.
            for byte in &mut self.files[idx].data[old_size..new_size] {
                *byte = 0;
            }
        }

        self.files[idx].size = new_size;
        self.stats.resize_count += 1;
        self.update_total_bytes();

        Ok(())
    }

    /// Returns the current size of a memfd.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `fd` is not registered.
    pub fn get_size(&self, fd: u32) -> Result<usize> {
        let idx = self.find_fd_index(fd)?;
        Ok(self.files[idx].size)
    }

    // ---------------------------------------------------------------
    // Read / Write
    // ---------------------------------------------------------------

    /// Writes data to a memfd at the given offset.
    ///
    /// Enforces `F_SEAL_WRITE`. If the write would extend past the
    /// current size, the file is implicitly grown (unless
    /// `F_SEAL_GROW` is set).
    ///
    /// Returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `fd` is not registered.
    /// - [`Error::PermissionDenied`] if `F_SEAL_WRITE` is set.
    /// - [`Error::InvalidArgument`] if `offset + data.len()` would
    ///   exceed [`MAX_MEMFD_DATA`].
    pub fn write(&mut self, fd: u32, offset: usize, data: &[u8]) -> Result<usize> {
        let idx = self.find_fd_index(fd)?;

        if self.files[idx].has_seal(seal_flags::F_SEAL_WRITE) {
            return Err(Error::PermissionDenied);
        }

        let end = offset
            .checked_add(data.len())
            .ok_or(Error::InvalidArgument)?;
        if end > MAX_MEMFD_DATA {
            return Err(Error::InvalidArgument);
        }

        // Implicit grow check.
        if end > self.files[idx].size {
            if self.files[idx].has_seal(seal_flags::F_SEAL_GROW) {
                return Err(Error::PermissionDenied);
            }
            // Zero-fill gap if offset > current size.
            let current = self.files[idx].size;
            if offset > current {
                for byte in &mut self.files[idx].data[current..offset] {
                    *byte = 0;
                }
            }
            self.files[idx].size = end;
        }

        self.files[idx].data[offset..end].copy_from_slice(data);
        self.files[idx].write_count += 1;
        self.stats.write_count += 1;
        self.update_total_bytes();

        Ok(data.len())
    }

    /// Reads data from a memfd at the given offset.
    ///
    /// Returns the number of bytes read (may be less than `buf.len()`
    /// if the read extends past the file size).
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `fd` is not registered.
    /// - [`Error::InvalidArgument`] if `offset` is beyond the file
    ///   size.
    pub fn read(&mut self, fd: u32, offset: usize, buf: &mut [u8]) -> Result<usize> {
        let idx = self.find_fd_index(fd)?;
        let size = self.files[idx].size;

        if offset >= size {
            return Err(Error::InvalidArgument);
        }

        let available = size - offset;
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&self.files[idx].data[offset..offset + to_read]);
        self.files[idx].read_count += 1;
        self.stats.read_count += 1;

        Ok(to_read)
    }

    // ---------------------------------------------------------------
    // Mapping management
    // ---------------------------------------------------------------

    /// Records a new mapping for a memfd.
    ///
    /// Enforces `F_SEAL_FUTURE_WRITE` by rejecting new writable
    /// mappings when that seal is set. Transitions the memfd to
    /// `Mapped` state.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `fd` is not registered.
    /// - [`Error::PermissionDenied`] if `writable` is true and
    ///   `F_SEAL_FUTURE_WRITE` or `F_SEAL_WRITE` is set.
    /// - [`Error::OutOfMemory`] if the mapping table is full.
    pub fn add_mapping(
        &mut self,
        fd: u32,
        pid: u64,
        virt_addr: u64,
        size: usize,
        writable: bool,
    ) -> Result<usize> {
        let idx = self.find_fd_index(fd)?;

        if writable {
            if self.files[idx].has_seal(seal_flags::F_SEAL_WRITE) {
                return Err(Error::PermissionDenied);
            }
            if self.files[idx].has_seal(seal_flags::F_SEAL_FUTURE_WRITE) {
                return Err(Error::PermissionDenied);
            }
        }

        let file = &mut self.files[idx];
        let map_idx = file
            .mappings
            .iter()
            .position(|m| !m.active)
            .ok_or(Error::OutOfMemory)?;

        file.mappings[map_idx] = MappingRecord {
            pid,
            virt_addr,
            size,
            writable,
            active: true,
        };
        file.mapping_count += 1;
        file.state = MemfdState::Mapped;

        self.stats.total_mappings += 1;

        Ok(map_idx)
    }

    /// Removes a mapping by its index within the memfd.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `fd` is not registered.
    /// - [`Error::InvalidArgument`] if the mapping index is out of
    ///   range or not active.
    pub fn remove_mapping(&mut self, fd: u32, map_idx: usize) -> Result<()> {
        let idx = self.find_fd_index(fd)?;

        if map_idx >= MAX_MAPPINGS_PER_FD {
            return Err(Error::InvalidArgument);
        }
        if !self.files[idx].mappings[map_idx].active {
            return Err(Error::InvalidArgument);
        }

        self.files[idx].mappings[map_idx] = MappingRecord::empty();
        self.files[idx].mapping_count = self.files[idx].mapping_count.saturating_sub(1);
        self.stats.total_mappings = self.stats.total_mappings.saturating_sub(1);

        // If no more mappings, transition back to Open.
        if self.files[idx].mapping_count == 0 {
            self.files[idx].state = MemfdState::Open;
        }

        Ok(())
    }

    // ---------------------------------------------------------------
    // Lifecycle: duplicate / close / destroy
    // ---------------------------------------------------------------

    /// Increments the reference count (fd duplication).
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `fd` is not registered.
    pub fn dup(&mut self, fd: u32) -> Result<()> {
        let idx = self.find_fd_index(fd)?;
        self.files[idx].ref_count += 1;
        Ok(())
    }

    /// Decrements the reference count. If it reaches zero, the memfd
    /// is destroyed.
    ///
    /// Returns `true` if the memfd was destroyed.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `fd` is not registered.
    pub fn close(&mut self, fd: u32) -> Result<bool> {
        let idx = self.find_fd_index(fd)?;
        self.files[idx].ref_count = self.files[idx].ref_count.saturating_sub(1);
        if self.files[idx].ref_count == 0 {
            self.destroy_slot(idx);
            return Ok(true);
        }
        Ok(false)
    }

    /// Destroys a memfd unconditionally (used during process cleanup).
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `fd` is not registered.
    pub fn destroy(&mut self, fd: u32) -> Result<()> {
        let idx = self.find_fd_index(fd)?;
        self.destroy_slot(idx);
        Ok(())
    }

    /// Internal: destroys the memfd in the given slot.
    fn destroy_slot(&mut self, idx: usize) {
        self.files[idx].state = MemfdState::Closing;

        // Clear mappings.
        let mapping_count = self.files[idx].mapping_count;
        self.stats.total_mappings = self.stats.total_mappings.saturating_sub(mapping_count);

        // Clear the slot.
        self.files[idx] = MemfdFile::empty();
        self.active_count = self.active_count.saturating_sub(1);
        self.stats.active_fds = self.active_count;
        self.stats.destroy_count += 1;
        self.update_total_bytes();
    }

    // ---------------------------------------------------------------
    // Process cleanup
    // ---------------------------------------------------------------

    /// Destroys all memfds owned by the given process.
    ///
    /// Returns the number of memfds destroyed.
    pub fn cleanup_process(&mut self, pid: u64) -> usize {
        let mut fds_to_destroy = [0u32; MAX_MEMFDS];
        let mut count = 0usize;

        for file in &self.files {
            if !file.is_inactive() && file.owner_pid == pid {
                fds_to_destroy[count] = file.fd;
                count += 1;
            }
        }

        let mut destroyed = 0usize;
        for &fd in &fds_to_destroy[..count] {
            if self.destroy(fd).is_ok() {
                destroyed += 1;
            }
        }
        destroyed
    }

    // ---------------------------------------------------------------
    // Queries
    // ---------------------------------------------------------------

    /// Returns information about a memfd.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `fd` is not registered.
    pub fn get_file(&self, fd: u32) -> Result<&MemfdFile> {
        let idx = self.find_fd_index(fd)?;
        Ok(&self.files[idx])
    }

    /// Returns the number of active memfd instances.
    pub fn active_count(&self) -> usize {
        self.active_count
    }

    /// Returns `true` if no memfds are active.
    pub fn is_empty(&self) -> bool {
        self.active_count == 0
    }

    /// Returns aggregate statistics.
    pub fn stats(&self) -> &MemfdStats {
        &self.stats
    }

    /// Returns the total number of pages consumed by all memfds.
    pub fn total_pages(&self) -> usize {
        let mut pages = 0usize;
        for file in &self.files {
            if !file.is_inactive() {
                pages += (file.size + PAGE_SIZE - 1) / PAGE_SIZE;
            }
        }
        pages
    }

    /// Finds a memfd by name. Returns the fd number of the first
    /// match.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no memfd with the given name exists.
    pub fn find_by_name(&self, name: &[u8]) -> Result<u32> {
        for file in &self.files {
            if !file.is_inactive() && file.name_bytes() == name {
                return Ok(file.fd);
            }
        }
        Err(Error::NotFound)
    }

    /// Lists all active memfd fd numbers owned by a process.
    ///
    /// Fills `out` with fd numbers and returns the count.
    pub fn list_for_process(&self, pid: u64, out: &mut [u32]) -> usize {
        let mut count = 0usize;
        for file in &self.files {
            if !file.is_inactive() && file.owner_pid == pid {
                if count < out.len() {
                    out[count] = file.fd;
                }
                count += 1;
            }
        }
        count.min(out.len())
    }

    /// Returns the total bytes of memory used by a specific process's
    /// memfds.
    pub fn bytes_for_process(&self, pid: u64) -> u64 {
        let mut total = 0u64;
        for file in &self.files {
            if !file.is_inactive() && file.owner_pid == pid {
                total += file.size as u64;
            }
        }
        total
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Finds the first free slot.
    fn find_free_slot(&self) -> Option<usize> {
        self.files.iter().position(|f| f.is_inactive())
    }

    /// Finds the index of an active memfd by its fd number.
    fn find_fd_index(&self, fd: u32) -> Result<usize> {
        self.files
            .iter()
            .position(|f| !f.is_inactive() && f.fd == fd)
            .ok_or(Error::NotFound)
    }

    /// Recomputes `stats.total_bytes`.
    fn update_total_bytes(&mut self) {
        let mut total = 0u64;
        for file in &self.files {
            if !file.is_inactive() {
                total += file.size as u64;
            }
        }
        self.stats.total_bytes = total;
    }
}
