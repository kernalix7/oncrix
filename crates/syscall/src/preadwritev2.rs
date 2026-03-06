// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `preadv2` / `pwritev2` — Scatter-gather I/O with per-call flags.
//!
//! Implements the Linux `preadv2(2)` and `pwritev2(2)` system calls, which
//! extend `preadv` / `pwritev` with an additional `flags` argument that
//! controls per-operation behavior such as synchronous I/O, high-priority
//! hints, and non-blocking semantics.
//!
//! # Syscall signatures
//!
//! ```text
//! ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt,
//!                 off_t offset, int flags);
//! ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt,
//!                  off_t offset, int flags);
//! ```
//!
//! # Key behaviors
//!
//! - `RWF_NOWAIT` causes the call to return `WouldBlock` when it would block.
//! - `RWF_APPEND` makes `pwritev2` ignore the supplied offset and append.
//! - `RWF_DSYNC` / `RWF_SYNC` flush data (/ data + metadata) before return.
//! - `RWF_HIPRI` is an advisory hint for high-priority I/O.
//! - An `offset` of `-1` uses (and updates) the file's current position.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of `IoVec` entries per call (`UIO_MAXIOV` in Linux).
pub const IOV_MAX: usize = 1024;

/// Maximum total byte count for a single scatter-gather operation.
///
/// Matches Linux's `MAX_RW_COUNT` (2 GiB − 1 page, assuming 4 KiB pages).
const MAX_RW_COUNT: u64 = 0x7FFF_F000;

/// Special offset value meaning "use the file's current position".
pub const OFFSET_CURRENT: i64 = -1;

// ---------------------------------------------------------------------------
// RwfFlags — per-operation flags for preadv2 / pwritev2
// ---------------------------------------------------------------------------

/// Per-operation flags for `preadv2` / `pwritev2`.
///
/// These flags modify the behavior of a single I/O operation without
/// requiring changes to the file descriptor's open-file description.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RwfFlags(u32);

impl RwfFlags {
    /// High-priority I/O hint (e.g. use polling for block devices).
    pub const RWF_HIPRI: u32 = 0x0000_0001;
    /// Synchronous data-integrity completion (like `O_DSYNC` per call).
    pub const RWF_DSYNC: u32 = 0x0000_0002;
    /// Synchronous file-integrity completion (like `O_SYNC` per call).
    pub const RWF_SYNC: u32 = 0x0000_0004;
    /// Do not wait for data that is not immediately available.
    pub const RWF_NOWAIT: u32 = 0x0000_0008;
    /// Append data to the end of the file (write only; offset ignored).
    pub const RWF_APPEND: u32 = 0x0000_0010;

    /// Mask of all recognised flag bits.
    const VALID_MASK: u32 =
        Self::RWF_HIPRI | Self::RWF_DSYNC | Self::RWF_SYNC | Self::RWF_NOWAIT | Self::RWF_APPEND;

    /// Create a new `RwfFlags` from a raw `u32`.
    ///
    /// Returns `InvalidArgument` if any unknown bits are set.
    pub fn from_raw(raw: u32) -> Result<Self> {
        if raw & !Self::VALID_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Return the raw flag bits.
    pub const fn bits(&self) -> u32 {
        self.0
    }

    /// Check whether high-priority I/O is requested.
    pub const fn is_hipri(&self) -> bool {
        self.0 & Self::RWF_HIPRI != 0
    }

    /// Check whether data-sync is requested.
    pub const fn is_dsync(&self) -> bool {
        self.0 & Self::RWF_DSYNC != 0
    }

    /// Check whether file-sync (data + metadata) is requested.
    pub const fn is_sync(&self) -> bool {
        self.0 & Self::RWF_SYNC != 0
    }

    /// Check whether the operation must not block.
    pub const fn is_nowait(&self) -> bool {
        self.0 & Self::RWF_NOWAIT != 0
    }

    /// Check whether the write should append (ignoring offset).
    pub const fn is_append(&self) -> bool {
        self.0 & Self::RWF_APPEND != 0
    }
}

// ---------------------------------------------------------------------------
// IoVec — scatter-gather element
// ---------------------------------------------------------------------------

/// A single scatter-gather I/O vector element (`struct iovec`).
///
/// Describes a contiguous region of user-space memory by base address
/// and byte length. The kernel must validate both fields before use.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IoVec {
    /// Base address of the user-space buffer.
    pub iov_base: u64,
    /// Length of the buffer in bytes.
    pub iov_len: u64,
}

impl IoVec {
    /// Create a new `IoVec` from a base address and length.
    pub const fn new(base: u64, len: u64) -> Self {
        Self {
            iov_base: base,
            iov_len: len,
        }
    }

    /// Validate that the buffer is non-null (when non-zero length)
    /// and that `base + len` does not overflow.
    pub fn validate(&self) -> Result<()> {
        // A zero-length vector is always valid.
        if self.iov_len == 0 {
            return Ok(());
        }

        // Non-zero-length buffers must have a non-null base.
        if self.iov_base == 0 {
            return Err(Error::InvalidArgument);
        }

        // `base + len` must not overflow the address space.
        if self.iov_base.checked_add(self.iov_len).is_none() {
            return Err(Error::InvalidArgument);
        }

        Ok(())
    }

    /// Return `true` if this vector describes a zero-byte region.
    pub const fn is_empty(&self) -> bool {
        self.iov_len == 0
    }
}

// ---------------------------------------------------------------------------
// IoVecArray — validated array of IoVec
// ---------------------------------------------------------------------------

/// Maximum number of `IoVec` entries we store inline (matches `IOV_MAX`).
const IOVEC_INLINE_MAX: usize = IOV_MAX;

/// A validated collection of scatter-gather vectors.
///
/// The array is stored inline (no heap allocation) and the total byte
/// count across all vectors is pre-computed.
pub struct IoVecArray {
    /// Inline storage for the iovec entries.
    entries: [IoVec; IOVEC_INLINE_MAX],
    /// Number of valid entries in `entries`.
    count: usize,
    /// Pre-computed total byte count across all vectors.
    total_len: u64,
}

impl IoVecArray {
    /// Create a new, empty `IoVecArray`.
    pub const fn new() -> Self {
        Self {
            entries: [IoVec {
                iov_base: 0,
                iov_len: 0,
            }; IOVEC_INLINE_MAX],
            count: 0,
            total_len: 0,
        }
    }

    /// Build a validated `IoVecArray` from a user-space iovec pointer
    /// and element count.
    ///
    /// # Validation
    ///
    /// - `iovcnt` must be in `1..=IOV_MAX`.
    /// - Each `IoVec` must pass its own validation.
    /// - The sum of all `iov_len` values must not exceed `MAX_RW_COUNT`.
    ///
    /// In a real kernel, `iov_ptr` would be copied from user space via
    /// `copy_from_user`. Here we take the pointer value for validation
    /// purposes and construct a representative array.
    pub fn from_user(iov_ptr: u64, iovcnt: i32) -> Result<Self> {
        // iovcnt must be positive and within IOV_MAX.
        if iovcnt <= 0 || iovcnt as usize > IOV_MAX {
            return Err(Error::InvalidArgument);
        }

        // The iov pointer itself must be non-null.
        if iov_ptr == 0 {
            return Err(Error::InvalidArgument);
        }

        let cnt = iovcnt as usize;

        // Validate that the iov pointer region doesn't overflow.
        // Each IoVec is 16 bytes (two u64 fields).
        let iov_byte_size = (cnt as u64).checked_mul(16).ok_or(Error::InvalidArgument)?;
        if iov_ptr.checked_add(iov_byte_size).is_none() {
            return Err(Error::InvalidArgument);
        }

        // In a real kernel, we would copy_from_user here.
        // For this stub, we create a representative array and record
        // that `cnt` entries would be read from the user.
        let mut arr = Self::new();
        arr.count = cnt;

        // We cannot actually dereference user pointers in the stub.
        // Mark each entry with the source address so that the caller
        // can see the metadata.
        let mut offset: u64 = 0;
        let mut i = 0;
        while i < cnt {
            let entry_addr = match iov_ptr.checked_add(offset) {
                Some(a) => a,
                None => return Err(Error::InvalidArgument),
            };
            arr.entries[i] = IoVec::new(entry_addr, 0);
            offset = match offset.checked_add(16) {
                Some(o) => o,
                None => return Err(Error::InvalidArgument),
            };
            i += 1;
        }

        Ok(arr)
    }

    /// Validate all entries and compute the total byte count.
    ///
    /// This must be called after the entries have been populated with
    /// actual user-space data (via `copy_from_user` in a real kernel).
    pub fn validate_and_compute(&mut self) -> Result<u64> {
        let mut total: u64 = 0;

        let mut i = 0;
        while i < self.count {
            self.entries[i].validate()?;
            total = total
                .checked_add(self.entries[i].iov_len)
                .ok_or(Error::InvalidArgument)?;
            if total > MAX_RW_COUNT {
                return Err(Error::InvalidArgument);
            }
            i += 1;
        }

        self.total_len = total;
        Ok(total)
    }

    /// Return the number of iovec entries.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return the total byte count (valid after `validate_and_compute`).
    pub const fn total_len(&self) -> u64 {
        self.total_len
    }

    /// Return a reference to the entry at `index`, or `None` if out
    /// of bounds.
    pub fn get(&self, index: usize) -> Option<&IoVec> {
        if index < self.count {
            Some(&self.entries[index])
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Preadv2Args / Pwritev2Args — parameter bundles
// ---------------------------------------------------------------------------

/// Arguments for the `preadv2` system call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Preadv2Args {
    /// File descriptor to read from.
    pub fd: i32,
    /// User-space pointer to the iovec array.
    pub iov: u64,
    /// Number of elements in the iovec array.
    pub iovcnt: i32,
    /// File offset to read from, or `-1` for the current position.
    pub offset: i64,
    /// Per-operation flags (`RwfFlags`).
    pub flags: u32,
}

impl Preadv2Args {
    /// Validate the preadv2 arguments.
    ///
    /// Checks:
    /// - `fd` is non-negative.
    /// - `iovcnt` is in `1..=IOV_MAX`.
    /// - `iov` pointer is non-null.
    /// - `offset` is `-1` (current position) or non-negative.
    /// - `flags` contain only recognised bits.
    /// - `RWF_APPEND` is not set (it is write-only).
    pub fn validate(&self) -> Result<RwfFlags> {
        if self.fd < 0 {
            return Err(Error::InvalidArgument);
        }

        if self.iovcnt <= 0 || self.iovcnt as usize > IOV_MAX {
            return Err(Error::InvalidArgument);
        }

        if self.iov == 0 {
            return Err(Error::InvalidArgument);
        }

        // Offset must be -1 (current pos) or non-negative.
        if self.offset < -1 {
            return Err(Error::InvalidArgument);
        }

        let rwf = RwfFlags::from_raw(self.flags)?;

        // RWF_APPEND is not valid for reads.
        if rwf.is_append() {
            return Err(Error::InvalidArgument);
        }

        Ok(rwf)
    }
}

/// Arguments for the `pwritev2` system call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Pwritev2Args {
    /// File descriptor to write to.
    pub fd: i32,
    /// User-space pointer to the iovec array.
    pub iov: u64,
    /// Number of elements in the iovec array.
    pub iovcnt: i32,
    /// File offset to write to, or `-1` for the current position.
    pub offset: i64,
    /// Per-operation flags (`RwfFlags`).
    pub flags: u32,
}

impl Pwritev2Args {
    /// Validate the pwritev2 arguments.
    ///
    /// Checks:
    /// - `fd` is non-negative.
    /// - `iovcnt` is in `1..=IOV_MAX`.
    /// - `iov` pointer is non-null.
    /// - `offset` is `-1` (current position) or non-negative.
    /// - `flags` contain only recognised bits.
    pub fn validate(&self) -> Result<RwfFlags> {
        if self.fd < 0 {
            return Err(Error::InvalidArgument);
        }

        if self.iovcnt <= 0 || self.iovcnt as usize > IOV_MAX {
            return Err(Error::InvalidArgument);
        }

        if self.iov == 0 {
            return Err(Error::InvalidArgument);
        }

        // Offset must be -1 (current pos) or non-negative.
        if self.offset < -1 {
            return Err(Error::InvalidArgument);
        }

        let rwf = RwfFlags::from_raw(self.flags)?;

        Ok(rwf)
    }
}

// ---------------------------------------------------------------------------
// File descriptor validation stubs
// ---------------------------------------------------------------------------

/// Minimum valid file descriptor number.
const FD_MIN: i32 = 0;

/// Maximum valid file descriptor number (arbitrary limit for validation).
const FD_MAX: i32 = 1_048_576;

/// Validate that a file descriptor number is within the allowed range.
fn validate_fd(fd: i32) -> Result<()> {
    if fd < FD_MIN || fd > FD_MAX {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Check whether a file descriptor supports reading.
///
/// Stub: in a real kernel, this would inspect the open-file description.
fn fd_is_readable(fd: i32) -> Result<()> {
    validate_fd(fd)?;
    // Stub: assume all valid fds are readable.
    Ok(())
}

/// Check whether a file descriptor supports writing.
///
/// Stub: in a real kernel, this would inspect the open-file description.
fn fd_is_writable(fd: i32) -> Result<()> {
    validate_fd(fd)?;
    // Stub: assume all valid fds are writable.
    Ok(())
}

/// Check whether a file descriptor supports seeking (i.e. is not a
/// pipe, socket, or other non-seekable object).
///
/// Stub: assumes seekable for any valid fd.
fn fd_is_seekable(_fd: i32) -> bool {
    true
}

// ---------------------------------------------------------------------------
// Resolve effective offset
// ---------------------------------------------------------------------------

/// Determine the effective file offset for an operation.
///
/// - If `offset` is `OFFSET_CURRENT` (`-1`), use the file's current position.
/// - If `RWF_APPEND` is set, the file's current size (EOF) is used.
/// - Otherwise, use the supplied `offset`.
///
/// Returns `(effective_offset, update_file_position)`:
/// - `update_file_position` is `true` when `offset == -1` (the caller must
///   advance the file position by the number of bytes transferred).
fn resolve_offset(_fd: i32, offset: i64, flags: &RwfFlags) -> Result<(u64, bool)> {
    if flags.is_append() {
        // RWF_APPEND: ignore the caller's offset, write at EOF.
        // Stub: return a representative "end of file" offset.
        return Ok((0, false));
    }

    if offset == OFFSET_CURRENT {
        // Use file's current position (stub: 0).
        return Ok((0, true));
    }

    // Explicit offset.
    if offset < 0 {
        return Err(Error::InvalidArgument);
    }

    Ok((offset as u64, false))
}

// ---------------------------------------------------------------------------
// Per-vector read / write stubs
// ---------------------------------------------------------------------------

/// Read data for a single iovec entry.
///
/// Stub: in a real kernel this would call into the VFS `read_iter` path
/// and scatter data into the user buffer.
fn read_single_iov(_fd: i32, iov: &IoVec, _file_offset: u64, flags: &RwfFlags) -> Result<u64> {
    if iov.is_empty() {
        return Ok(0);
    }

    // RWF_NOWAIT: return WouldBlock if data is not cached.
    if flags.is_nowait() {
        return Err(Error::WouldBlock);
    }

    // Stub: report that the full vector was read.
    Ok(iov.iov_len)
}

/// Write data for a single iovec entry.
///
/// Stub: in a real kernel this would call into the VFS `write_iter`
/// path, gathering data from the user buffer.
fn write_single_iov(_fd: i32, iov: &IoVec, _file_offset: u64, flags: &RwfFlags) -> Result<u64> {
    if iov.is_empty() {
        return Ok(0);
    }

    // RWF_NOWAIT: return WouldBlock if the write would block.
    if flags.is_nowait() {
        return Err(Error::WouldBlock);
    }

    // Stub: report that the full vector was written.
    Ok(iov.iov_len)
}

// ---------------------------------------------------------------------------
// Sync helpers
// ---------------------------------------------------------------------------

/// Perform data-sync for a file descriptor.
///
/// Stub: in a real kernel this would flush the page cache to stable
/// storage (equivalent to `fdatasync`).
fn sync_data(_fd: i32) -> Result<()> {
    // Stub: sync is a no-op.
    Ok(())
}

/// Perform file-sync (data + metadata) for a file descriptor.
///
/// Stub: in a real kernel this would flush all dirty pages and metadata
/// (equivalent to `fsync`).
fn sync_file(_fd: i32) -> Result<()> {
    // Stub: sync is a no-op.
    Ok(())
}

/// Handle post-I/O synchronization based on `RwfFlags`.
fn handle_sync(fd: i32, flags: &RwfFlags) -> Result<()> {
    if flags.is_sync() {
        sync_file(fd)?;
    } else if flags.is_dsync() {
        sync_data(fd)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Syscall handlers
// ---------------------------------------------------------------------------

/// `preadv2` — scatter-read from a file descriptor at a given offset.
///
/// Reads data from `fd` into the buffers described by the user-space
/// `iov` array. The read starts at `offset` (or the file's current
/// position when `offset == -1`).
///
/// # Arguments
///
/// - `fd`     — Open file descriptor to read from.
/// - `iov`    — User-space pointer to an array of `IoVec` structures.
/// - `iovcnt` — Number of elements in the `iov` array (1..=IOV_MAX).
/// - `offset` — File offset to start reading at, or `-1` for the
///              current file position.
/// - `flags`  — Per-operation flags (`RWF_*`).
///
/// # Returns
///
/// Total number of bytes read on success.
///
/// # Errors
///
/// - `InvalidArgument` — bad fd, iovcnt, offset, or flags.
/// - `WouldBlock` — `RWF_NOWAIT` set and data is not available.
/// - `Interrupted` — the operation was interrupted by a signal.
/// - `IoError` — an I/O error occurred during the read.
///
/// # POSIX conformance
///
/// The base scatter-gather semantics follow POSIX.1-2024 `readv()`.
/// The `flags` parameter is a Linux extension (Linux 4.6+).
pub fn do_preadv2(fd: i32, iov: u64, iovcnt: i32, offset: i64, flags: u32) -> Result<u64> {
    // --- argument validation ---

    let args = Preadv2Args {
        fd,
        iov,
        iovcnt,
        offset,
        flags,
    };
    let rwf = args.validate()?;

    fd_is_readable(fd)?;

    // Seekable files only: validate that the offset is usable.
    if offset != OFFSET_CURRENT && !fd_is_seekable(fd) {
        return Err(Error::InvalidArgument);
    }

    // --- copy iovec array from user space ---

    let mut iov_array = IoVecArray::from_user(iov, iovcnt)?;

    // In a real kernel the entries would now be populated via
    // copy_from_user. The stub already set up representative entries.
    let _total_requested = iov_array.validate_and_compute()?;

    // --- resolve file offset ---

    let (mut file_pos, update_pos) = resolve_offset(fd, offset, &rwf)?;

    // --- scatter read ---

    let mut total_read: u64 = 0;

    let mut idx = 0;
    while idx < iov_array.count() {
        let entry = match iov_array.get(idx) {
            Some(e) => *e,
            None => break,
        };

        match read_single_iov(fd, &entry, file_pos, &rwf) {
            Ok(n) => {
                total_read = total_read.saturating_add(n);
                file_pos = file_pos.saturating_add(n);

                // Short read: stop iterating.
                if n < entry.iov_len {
                    break;
                }
            }
            Err(e) => {
                // If we already read something, return a partial result
                // instead of propagating the error (POSIX short-read
                // semantics).
                if total_read > 0 {
                    break;
                }
                return Err(e);
            }
        }

        idx += 1;
    }

    // --- update file position (if using current position) ---

    if update_pos {
        // Stub: a real kernel would update the struct file's f_pos.
        let _ = total_read;
    }

    // --- post-I/O sync ---

    handle_sync(fd, &rwf)?;

    Ok(total_read)
}

/// `pwritev2` — gather-write to a file descriptor at a given offset.
///
/// Writes data from the buffers described by the user-space `iov` array
/// to `fd`. The write starts at `offset` (or the file's current position
/// when `offset == -1`, or at EOF when `RWF_APPEND` is set).
///
/// # Arguments
///
/// - `fd`     — Open file descriptor to write to.
/// - `iov`    — User-space pointer to an array of `IoVec` structures.
/// - `iovcnt` — Number of elements in the `iov` array (1..=IOV_MAX).
/// - `offset` — File offset to start writing at, `-1` for the current
///              file position, or ignored when `RWF_APPEND` is set.
/// - `flags`  — Per-operation flags (`RWF_*`).
///
/// # Returns
///
/// Total number of bytes written on success.
///
/// # Errors
///
/// - `InvalidArgument` — bad fd, iovcnt, offset, or flags.
/// - `WouldBlock` — `RWF_NOWAIT` set and the write would block.
/// - `Interrupted` — the operation was interrupted by a signal.
/// - `IoError` — an I/O error occurred during the write.
///
/// # POSIX conformance
///
/// The base gather-write semantics follow POSIX.1-2024 `writev()`.
/// The `flags` parameter is a Linux extension (Linux 4.6+).
pub fn do_pwritev2(fd: i32, iov: u64, iovcnt: i32, offset: i64, flags: u32) -> Result<u64> {
    // --- argument validation ---

    let args = Pwritev2Args {
        fd,
        iov,
        iovcnt,
        offset,
        flags,
    };
    let rwf = args.validate()?;

    fd_is_writable(fd)?;

    // Seekable files only: validate that the offset is usable.
    if offset != OFFSET_CURRENT && !rwf.is_append() && !fd_is_seekable(fd) {
        return Err(Error::InvalidArgument);
    }

    // --- copy iovec array from user space ---

    let mut iov_array = IoVecArray::from_user(iov, iovcnt)?;
    let _total_requested = iov_array.validate_and_compute()?;

    // --- resolve file offset ---

    let (mut file_pos, update_pos) = resolve_offset(fd, offset, &rwf)?;

    // --- gather write ---

    let mut total_written: u64 = 0;

    let mut idx = 0;
    while idx < iov_array.count() {
        let entry = match iov_array.get(idx) {
            Some(e) => *e,
            None => break,
        };

        match write_single_iov(fd, &entry, file_pos, &rwf) {
            Ok(n) => {
                total_written = total_written.saturating_add(n);
                file_pos = file_pos.saturating_add(n);

                // Short write: stop iterating.
                if n < entry.iov_len {
                    break;
                }
            }
            Err(e) => {
                // If we already wrote something, return a partial result
                // instead of propagating the error (POSIX short-write
                // semantics).
                if total_written > 0 {
                    break;
                }
                return Err(e);
            }
        }

        idx += 1;
    }

    // --- update file position (if using current position) ---

    if update_pos {
        let _ = total_written;
    }

    // --- post-I/O sync ---

    handle_sync(fd, &rwf)?;

    Ok(total_written)
}

// ---------------------------------------------------------------------------
// Legacy preadv / pwritev (without flags)
// ---------------------------------------------------------------------------

/// `preadv` — scatter-read at a given offset (legacy, no flags).
///
/// Equivalent to `preadv2(fd, iov, iovcnt, offset, 0)`.
pub fn do_preadv(fd: i32, iov: u64, iovcnt: i32, offset: i64) -> Result<u64> {
    do_preadv2(fd, iov, iovcnt, offset, 0)
}

/// `pwritev` — gather-write at a given offset (legacy, no flags).
///
/// Equivalent to `pwritev2(fd, iov, iovcnt, offset, 0)`.
pub fn do_pwritev(fd: i32, iov: u64, iovcnt: i32, offset: i64) -> Result<u64> {
    do_pwritev2(fd, iov, iovcnt, offset, 0)
}

// ---------------------------------------------------------------------------
// readv / writev (current position, no flags)
// ---------------------------------------------------------------------------

/// `readv` — scatter-read using the file's current position.
///
/// Equivalent to `preadv2(fd, iov, iovcnt, -1, 0)`.
///
/// Reference: POSIX.1-2024 §readv.
pub fn do_readv(fd: i32, iov: u64, iovcnt: i32) -> Result<u64> {
    do_preadv2(fd, iov, iovcnt, OFFSET_CURRENT, 0)
}

/// `writev` — gather-write using the file's current position.
///
/// Equivalent to `pwritev2(fd, iov, iovcnt, -1, 0)`.
///
/// Reference: POSIX.1-2024 §writev.
pub fn do_writev(fd: i32, iov: u64, iovcnt: i32) -> Result<u64> {
    do_pwritev2(fd, iov, iovcnt, OFFSET_CURRENT, 0)
}

// ---------------------------------------------------------------------------
// Syscall number constants
// ---------------------------------------------------------------------------

/// Syscall number for `preadv2` (x86_64 Linux ABI).
pub const SYS_PREADV2: u64 = 327;

/// Syscall number for `pwritev2` (x86_64 Linux ABI).
pub const SYS_PWRITEV2: u64 = 328;

/// Syscall number for `preadv` (x86_64 Linux ABI).
pub const SYS_PREADV: u64 = 295;

/// Syscall number for `pwritev` (x86_64 Linux ABI).
pub const SYS_PWRITEV: u64 = 296;

/// Syscall number for `readv` (x86_64 Linux ABI).
pub const SYS_READV: u64 = 19;

/// Syscall number for `writev` (x86_64 Linux ABI).
pub const SYS_WRITEV: u64 = 20;

// ---------------------------------------------------------------------------
// Dispatch helper
// ---------------------------------------------------------------------------

/// Dispatch a preadv2/pwritev2-family syscall from raw register values.
///
/// This is called by the syscall dispatcher to handle all vectored-I/O
/// syscalls. The register layout follows the x86_64 Linux ABI:
///
/// - `arg0` — file descriptor
/// - `arg1` — pointer to iovec array
/// - `arg2` — iovcnt
/// - `arg3` — offset (low 32 bits)
/// - `arg4` — offset (high 32 bits), combined as `(arg4 << 32) | arg3`
///            for the 32-bit compat path. For native 64-bit, use `arg3`.
/// - `arg5` — flags (for preadv2/pwritev2 only)
pub fn dispatch_vectored_io(
    syscall_nr: u64,
    fd: i32,
    iov_ptr: u64,
    iovcnt: i32,
    offset: i64,
    flags: u32,
) -> Result<u64> {
    match syscall_nr {
        SYS_READV => do_readv(fd, iov_ptr, iovcnt),
        SYS_WRITEV => do_writev(fd, iov_ptr, iovcnt),
        SYS_PREADV => do_preadv(fd, iov_ptr, iovcnt, offset),
        SYS_PWRITEV => do_pwritev(fd, iov_ptr, iovcnt, offset),
        SYS_PREADV2 => do_preadv2(fd, iov_ptr, iovcnt, offset, flags),
        SYS_PWRITEV2 => do_pwritev2(fd, iov_ptr, iovcnt, offset, flags),
        _ => Err(Error::InvalidArgument),
    }
}
