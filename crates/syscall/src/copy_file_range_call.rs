// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `copy_file_range(2)` syscall handler.
//!
//! `copy_file_range` (Linux 4.5) copies a range of data between two file
//! descriptors, potentially entirely within the kernel using
//! server-side-copy or reflink operations.  When both file descriptors
//! refer to files on the same filesystem, the kernel can bypass the
//! page cache and delegate the copy to the filesystem driver, producing
//! zero-copy or copy-on-write (reflink) semantics.
//!
//! # POSIX context
//!
//! `copy_file_range` is a Linux extension.  POSIX.1-2024 does not define
//! this syscall, but it is widely used in container runtimes, archive tools,
//! and file managers.  The semantics follow Linux's `copy_file_range(2)`
//! man-page exactly.
//!
//! # Key behaviours
//!
//! - Both `fd_in` and `fd_out` must be open for reading/writing respectively.
//! - `off_in` / `off_out` are optional; `None` means "use the current file
//!   position" (which is then advanced by `len` on success).
//! - Copying a range that exceeds the source file size copies only what is
//!   available and returns a short count — it is not an error.
//! - `flags` must be 0 (reserved for future use).
//! - The two file descriptors may refer to the same file; overlapping ranges
//!   are permitted.
//!
//! # Key types
//!
//! - [`CopyRange`]  — validated source/destination range description
//! - [`CopyFlags`]  — typed, validated flags wrapper
//! - [`CopyResult`] — result of a successful copy operation
//!
//! # Kernel data flow
//!
//! ```text
//! user space                       kernel space
//! ──────────                       ─────────────
//! copy_file_range(fd_in, off_in,   validate(fd_in, fd_out, len, flags)
//!                 fd_out, off_out, → CopyRange::from_raw()
//!                 len, flags)      → do_copy_file_range_validated()
//!                              ◄── CopyResult / -errno
//! ```
//!
//! # References
//!
//! - Linux: `fs/copy_range.c` — `vfs_copy_file_range()`
//! - man-pages: `copy_file_range(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// File descriptor capability flags (stub)
// ---------------------------------------------------------------------------

/// File is open for reading.
pub const FILE_READABLE: u32 = 1 << 0;
/// File is open for writing.
pub const FILE_WRITABLE: u32 = 1 << 1;
/// File is a regular file (not a special file, socket, or pipe).
pub const FILE_REGULAR: u32 = 1 << 2;
/// File resides on a filesystem that supports server-side copy.
pub const FILE_SUPPORTS_COPY: u32 = 1 << 3;

// ---------------------------------------------------------------------------
// FileDescriptor stub
// ---------------------------------------------------------------------------

/// Maximum number of file descriptors in the stub table.
pub const MAX_FILE_DESCRIPTORS: usize = 64;

/// Maximum file size supported by the stub.
pub const MAX_FILE_SIZE: u64 = 1 << 40; // 1 TiB

/// A stub representation of an open file descriptor.
#[derive(Debug, Clone, Copy)]
pub struct FileDescriptor {
    /// Numeric file descriptor.
    pub fd: i32,
    /// Capability flags (`FILE_READABLE`, `FILE_WRITABLE`, etc.).
    pub caps: u32,
    /// File size in bytes (logical).
    pub size: u64,
    /// Current file position (used when `off_in`/`off_out` is `None`).
    pub position: u64,
    /// Filesystem ID (used to check if two fds are on the same fs).
    pub fs_id: u64,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl FileDescriptor {
    /// Create an empty, unused descriptor slot.
    const fn empty() -> Self {
        Self {
            fd: -1,
            caps: 0,
            size: 0,
            position: 0,
            fs_id: 0,
            in_use: false,
        }
    }
}

/// A stub table of open file descriptors.
pub struct FdTable {
    fds: [FileDescriptor; MAX_FILE_DESCRIPTORS],
    count: usize,
}

impl FdTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            fds: [const { FileDescriptor::empty() }; MAX_FILE_DESCRIPTORS],
            count: 0,
        }
    }

    /// Register a file descriptor.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfMemory`] — table full.
    pub fn insert(&mut self, desc: FileDescriptor) -> Result<()> {
        for slot in self.fds.iter_mut() {
            if !slot.in_use {
                *slot = desc;
                slot.in_use = true;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up a descriptor by `fd` number.
    pub fn find(&self, fd: i32) -> Option<&FileDescriptor> {
        self.fds.iter().find(|d| d.in_use && d.fd == fd)
    }

    /// Look up a descriptor by `fd` number (mutable).
    pub fn find_mut(&mut self, fd: i32) -> Option<&mut FileDescriptor> {
        self.fds.iter_mut().find(|d| d.in_use && d.fd == fd)
    }

    /// Remove (close) a descriptor.
    pub fn remove(&mut self, fd: i32) {
        for slot in self.fds.iter_mut() {
            if slot.in_use && slot.fd == fd {
                *slot = FileDescriptor::empty();
                self.count = self.count.saturating_sub(1);
                return;
            }
        }
    }

    /// Return the number of open descriptors.
    pub const fn count(&self) -> usize {
        self.count
    }
}

// ---------------------------------------------------------------------------
// CopyFlags — validated flags for copy_file_range
// ---------------------------------------------------------------------------

/// Validated flags for `copy_file_range(2)`.
///
/// Currently all flags are reserved (must be 0). This type provides
/// forward-compatible typed flag handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CopyFlags(u32);

impl CopyFlags {
    /// Construct from raw flags.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if any bits are set (all reserved).
    pub fn from_raw(raw: u32) -> Result<Self> {
        if raw != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Return the raw bit pattern.
    pub const fn bits(&self) -> u32 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// CopyRange — validated source/destination range
// ---------------------------------------------------------------------------

/// Validated source/destination range for `copy_file_range`.
///
/// Encapsulates the two file descriptors, their offsets, and the
/// requested length after all validation has been performed.
#[derive(Debug, Clone, Copy)]
pub struct CopyRange {
    /// Source file descriptor number.
    pub fd_in: i32,
    /// Source offset (resolved from explicit or implicit position).
    pub off_in: u64,
    /// Whether the source offset was explicitly provided.
    pub off_in_explicit: bool,
    /// Destination file descriptor number.
    pub fd_out: i32,
    /// Destination offset (resolved from explicit or implicit position).
    pub off_out: u64,
    /// Whether the destination offset was explicitly provided.
    pub off_out_explicit: bool,
    /// Requested copy length in bytes.
    pub len: u64,
}

impl CopyRange {
    /// Construct a validated copy range from raw syscall arguments.
    ///
    /// Resolves implicit offsets from the file descriptors' current
    /// positions, validates that both fds exist and have the correct
    /// capabilities, and checks for same-file overlap.
    ///
    /// # Arguments
    ///
    /// * `table`   — open file descriptor table
    /// * `fd_in`   — source fd (must be readable + regular)
    /// * `off_in`  — explicit source offset, or `None` for current pos
    /// * `fd_out`  — destination fd (must be writable + regular)
    /// * `off_out` — explicit destination offset, or `None` for current pos
    /// * `len`     — requested byte count
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — zero len, oversize offset/len, overlap
    /// * `NotFound` — fd not in table
    /// * `PermissionDenied` — missing read/write capability
    /// * `IoError` — not a regular file
    pub fn from_raw(
        table: &FdTable,
        fd_in: i32,
        off_in: Option<u64>,
        fd_out: i32,
        off_out: Option<u64>,
        len: u64,
    ) -> Result<Self> {
        // Validate length.
        if len == 0 || len > MAX_FILE_SIZE {
            return Err(Error::InvalidArgument);
        }

        // Look up descriptors.
        let in_desc = table.find(fd_in).ok_or(Error::NotFound)?;
        let out_desc = table.find(fd_out).ok_or(Error::NotFound)?;

        // Capability checks.
        if in_desc.caps & FILE_READABLE == 0 {
            return Err(Error::PermissionDenied);
        }
        if out_desc.caps & FILE_WRITABLE == 0 {
            return Err(Error::PermissionDenied);
        }
        if in_desc.caps & FILE_REGULAR == 0 || out_desc.caps & FILE_REGULAR == 0 {
            return Err(Error::IoError);
        }

        // Resolve offsets.
        let (src_off, src_explicit) = match off_in {
            Some(o) => {
                if o >= MAX_FILE_SIZE {
                    return Err(Error::InvalidArgument);
                }
                (o, true)
            }
            None => (in_desc.position, false),
        };

        let (dst_off, dst_explicit) = match off_out {
            Some(o) => {
                if o >= MAX_FILE_SIZE {
                    return Err(Error::InvalidArgument);
                }
                (o, true)
            }
            None => (out_desc.position, false),
        };

        // Same-file overlap check.
        if fd_in == fd_out {
            let src_end = src_off.saturating_add(len);
            let dst_end = dst_off.saturating_add(len);
            if src_off < dst_end && dst_off < src_end {
                return Err(Error::InvalidArgument);
            }
        }

        Ok(Self {
            fd_in,
            off_in: src_off,
            off_in_explicit: src_explicit,
            fd_out,
            off_out: dst_off,
            off_out_explicit: dst_explicit,
            len,
        })
    }

    /// Return whether source and destination are on the same filesystem.
    pub fn same_fs(&self, table: &FdTable) -> bool {
        let in_fs = table.find(self.fd_in).map(|d| d.fs_id);
        let out_fs = table.find(self.fd_out).map(|d| d.fs_id);
        match (in_fs, out_fs) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }

    /// Return whether the source fd supports server-side copy.
    pub fn supports_server_copy(&self, table: &FdTable) -> bool {
        table
            .find(self.fd_in)
            .map(|d| d.caps & FILE_SUPPORTS_COPY != 0)
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// CopyResult — result of a successful copy
// ---------------------------------------------------------------------------

/// Result of a successful `copy_file_range` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyResult {
    /// Number of bytes actually copied.
    pub bytes_copied: u64,
    /// New position in `fd_in` after the copy.
    pub new_off_in: u64,
    /// New position in `fd_out` after the copy.
    pub new_off_out: u64,
    /// Whether the copy was performed via server-side offload.
    pub server_side: bool,
    /// Whether the copy used reflink (copy-on-write) semantics.
    pub reflink: bool,
}

impl CopyResult {
    /// Return `true` if any bytes were copied.
    pub const fn has_data(&self) -> bool {
        self.bytes_copied > 0
    }

    /// Return `true` if the copy was short (fewer than requested).
    pub const fn is_short(&self, requested: u64) -> bool {
        self.bytes_copied < requested
    }
}

// ---------------------------------------------------------------------------
// do_copy_file_range_validated — main handler (pre-validated args)
// ---------------------------------------------------------------------------

/// Execute `copy_file_range` with a pre-validated [`CopyRange`].
///
/// This is the inner implementation that assumes all arguments have
/// already been validated by [`CopyRange::from_raw`].
///
/// # Arguments
///
/// * `table` — open file descriptor table
/// * `range` — validated copy range
///
/// # Returns
///
/// A [`CopyResult`] with the copy outcome.
fn do_copy_file_range_validated(table: &mut FdTable, range: &CopyRange) -> Result<CopyResult> {
    // Read the source file size.
    let in_desc = *table.find(range.fd_in).ok_or(Error::NotFound)?;

    // Compute how many bytes are actually available from src_off.
    let available = in_desc.size.saturating_sub(range.off_in);
    let bytes_to_copy = range.len.min(available);

    // Determine copy strategy.
    let same_fs = range.same_fs(table);
    let server_side = same_fs
        && table
            .find(range.fd_in)
            .map(|d| d.caps & FILE_SUPPORTS_COPY != 0)
            .unwrap_or(false);

    // In a real kernel: vfs_copy_file_range() -> on-disk reflink
    // or page-cache copy. Stub: just update positions/sizes.

    // Update fd_in position if offset was implicit.
    let new_off_in = range.off_in + bytes_to_copy;
    if !range.off_in_explicit {
        if let Some(desc) = table.find_mut(range.fd_in) {
            desc.position = new_off_in;
        }
    }

    // Update fd_out position / size.
    let new_off_out = range.off_out + bytes_to_copy;
    if let Some(desc) = table.find_mut(range.fd_out) {
        if new_off_out > desc.size {
            desc.size = new_off_out;
        }
        if !range.off_out_explicit {
            desc.position = new_off_out;
        }
    }

    Ok(CopyResult {
        bytes_copied: bytes_to_copy,
        new_off_in,
        new_off_out,
        server_side,
        reflink: false,
    })
}

// ---------------------------------------------------------------------------
// do_copy_file_range — public handler
// ---------------------------------------------------------------------------

/// Handler for `copy_file_range(2)`.
///
/// Copies up to `len` bytes from `fd_in` (starting at `off_in`, or the
/// current position if `None`) to `fd_out` (starting at `off_out`, or the
/// current position if `None`).
///
/// A short copy (fewer than `len` bytes) is returned when the source range
/// extends past the end of `fd_in`.  Copying 0 bytes is possible only when
/// `off_in` is already at or past `fd_in.size`.
///
/// # Arguments
///
/// * `table`   — Open file descriptor table.
/// * `fd_in`   — Source file descriptor (must be readable and regular).
/// * `off_in`  — Optional source offset; `None` = use `fd_in.position`.
/// * `fd_out`  — Destination file descriptor (must be writable and regular).
/// * `off_out` — Optional destination offset; `None` = use `fd_out.position`.
/// * `len`     — Number of bytes to copy.
/// * `flags`   — Reserved; must be 0.
///
/// # Returns
///
/// A [`CopyResult`] containing the number of bytes copied and the
/// updated offsets.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — Bad flags, invalid `len`, `fd_in == fd_out`
///   with overlapping ranges, negative or oversized offsets.
/// - [`Error::NotFound`]        — `fd_in` or `fd_out` not found in the table.
/// - [`Error::PermissionDenied`] — `fd_in` not readable or `fd_out` not writable.
/// - [`Error::IoError`]         — Not a regular file.
pub fn do_copy_file_range(
    table: &mut FdTable,
    fd_in: i32,
    off_in: Option<u64>,
    fd_out: i32,
    off_out: Option<u64>,
    len: u64,
    flags: u32,
) -> Result<CopyResult> {
    let _flags = CopyFlags::from_raw(flags)?;
    let range = CopyRange::from_raw(table, fd_in, off_in, fd_out, off_out, len)?;
    do_copy_file_range_validated(table, &range)
}

// ---------------------------------------------------------------------------
// do_copy_file_range_cross_fs
// ---------------------------------------------------------------------------

/// Fallback handler for cross-filesystem `copy_file_range`.
///
/// When `fd_in` and `fd_out` reside on different filesystems, the kernel
/// cannot use reflinks or server-side copy.  It falls back to a
/// read-into-kernel-buffer / write-from-kernel-buffer loop.
///
/// This stub delegates to [`do_copy_file_range`] since the result is
/// semantically identical; in a real kernel the implementation path differs.
pub fn do_copy_file_range_cross_fs(
    table: &mut FdTable,
    fd_in: i32,
    off_in: Option<u64>,
    fd_out: i32,
    off_out: Option<u64>,
    len: u64,
) -> Result<CopyResult> {
    do_copy_file_range(table, fd_in, off_in, fd_out, off_out, len, 0)
}

// ---------------------------------------------------------------------------
// Batched copy helper
// ---------------------------------------------------------------------------

/// Maximum chunk size for batched copies (4 MiB).
const BATCH_CHUNK_SIZE: u64 = 4 * 1024 * 1024;

/// Copy a large range in chunks.
///
/// Useful when copying very large files where the kernel wants to
/// yield between chunks for fairness or signal delivery.
///
/// # Arguments
///
/// * `table` — open file descriptor table
/// * `fd_in` — source fd
/// * `off_in` — starting source offset
/// * `fd_out` — destination fd
/// * `off_out` — starting destination offset
/// * `total_len` — total bytes to copy
///
/// # Returns
///
/// Total bytes copied across all chunks.
pub fn copy_file_range_batched(
    table: &mut FdTable,
    fd_in: i32,
    off_in: u64,
    fd_out: i32,
    off_out: u64,
    total_len: u64,
) -> Result<u64> {
    if total_len == 0 {
        return Err(Error::InvalidArgument);
    }

    let mut remaining = total_len;
    let mut src_pos = off_in;
    let mut dst_pos = off_out;
    let mut total_copied = 0u64;

    while remaining > 0 {
        let chunk = remaining.min(BATCH_CHUNK_SIZE);
        let result =
            do_copy_file_range(table, fd_in, Some(src_pos), fd_out, Some(dst_pos), chunk, 0)?;

        total_copied += result.bytes_copied;

        if result.bytes_copied == 0 {
            // Reached end of source.
            break;
        }

        src_pos = result.new_off_in;
        dst_pos = result.new_off_out;
        remaining = remaining.saturating_sub(result.bytes_copied);
    }

    Ok(total_copied)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_table() -> FdTable {
        let mut t = FdTable::new();
        // fd=3: readable, regular, 4096 bytes
        t.insert(FileDescriptor {
            fd: 3,
            caps: FILE_READABLE | FILE_REGULAR,
            size: 4096,
            position: 0,
            fs_id: 1,
            in_use: true,
        })
        .unwrap();
        // fd=4: writable, regular, 0 bytes
        t.insert(FileDescriptor {
            fd: 4,
            caps: FILE_WRITABLE | FILE_REGULAR,
            size: 0,
            position: 0,
            fs_id: 1,
            in_use: true,
        })
        .unwrap();
        t
    }

    #[test]
    fn copy_full_range() {
        let mut t = make_table();
        let r = do_copy_file_range(&mut t, 3, Some(0), 4, Some(0), 4096, 0).unwrap();
        assert_eq!(r.bytes_copied, 4096);
        assert_eq!(r.new_off_in, 4096);
        assert_eq!(r.new_off_out, 4096);
        assert_eq!(t.find(4).unwrap().size, 4096);
    }

    #[test]
    fn copy_partial_when_past_eof() {
        let mut t = make_table();
        let r = do_copy_file_range(&mut t, 3, Some(2048), 4, Some(0), 8192, 0).unwrap();
        assert_eq!(r.bytes_copied, 2048);
    }

    #[test]
    fn copy_at_eof_returns_zero() {
        let mut t = make_table();
        let r = do_copy_file_range(&mut t, 3, Some(4096), 4, Some(0), 100, 0).unwrap();
        assert_eq!(r.bytes_copied, 0);
    }

    #[test]
    fn copy_advances_implicit_positions() {
        let mut t = make_table();
        do_copy_file_range(&mut t, 3, None, 4, None, 512, 0).unwrap();
        assert_eq!(t.find(3).unwrap().position, 512);
        assert_eq!(t.find(4).unwrap().position, 512);
    }

    #[test]
    fn copy_does_not_advance_explicit_offsets() {
        let mut t = make_table();
        do_copy_file_range(&mut t, 3, Some(0), 4, Some(0), 512, 0).unwrap();
        assert_eq!(t.find(3).unwrap().position, 0);
        assert_eq!(t.find(4).unwrap().position, 0);
    }

    #[test]
    fn copy_extends_dst_size() {
        let mut t = make_table();
        do_copy_file_range(&mut t, 3, Some(0), 4, Some(100), 200, 0).unwrap();
        assert_eq!(t.find(4).unwrap().size, 300);
    }

    #[test]
    fn nonzero_flags_rejected() {
        let mut t = make_table();
        assert_eq!(
            do_copy_file_range(&mut t, 3, Some(0), 4, Some(0), 100, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn zero_len_rejected() {
        let mut t = make_table();
        assert_eq!(
            do_copy_file_range(&mut t, 3, Some(0), 4, Some(0), 0, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn missing_fd_in_returns_not_found() {
        let mut t = make_table();
        assert_eq!(
            do_copy_file_range(&mut t, 99, Some(0), 4, Some(0), 100, 0),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn missing_fd_out_returns_not_found() {
        let mut t = make_table();
        assert_eq!(
            do_copy_file_range(&mut t, 3, Some(0), 99, Some(0), 100, 0),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn non_readable_fd_in_rejected() {
        let mut t = make_table();
        t.insert(FileDescriptor {
            fd: 5,
            caps: FILE_WRITABLE | FILE_REGULAR,
            size: 1000,
            position: 0,
            fs_id: 1,
            in_use: true,
        })
        .unwrap();
        assert_eq!(
            do_copy_file_range(&mut t, 5, Some(0), 4, Some(0), 100, 0),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn non_writable_fd_out_rejected() {
        let mut t = make_table();
        t.insert(FileDescriptor {
            fd: 6,
            caps: FILE_READABLE | FILE_REGULAR,
            size: 0,
            position: 0,
            fs_id: 1,
            in_use: true,
        })
        .unwrap();
        assert_eq!(
            do_copy_file_range(&mut t, 3, Some(0), 6, Some(0), 100, 0),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn non_regular_file_rejected() {
        let mut t = make_table();
        t.insert(FileDescriptor {
            fd: 7,
            caps: FILE_READABLE | FILE_WRITABLE,
            size: 1000,
            position: 0,
            fs_id: 1,
            in_use: true,
        })
        .unwrap();
        assert_eq!(
            do_copy_file_range(&mut t, 7, Some(0), 4, Some(0), 100, 0),
            Err(Error::IoError)
        );
    }

    #[test]
    fn same_fd_overlapping_ranges_rejected() {
        let mut t = FdTable::new();
        t.insert(FileDescriptor {
            fd: 10,
            caps: FILE_READABLE | FILE_WRITABLE | FILE_REGULAR,
            size: 4096,
            position: 0,
            fs_id: 1,
            in_use: true,
        })
        .unwrap();
        assert_eq!(
            do_copy_file_range(&mut t, 10, Some(0), 10, Some(100), 200, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn same_fd_non_overlapping_ranges_ok() {
        let mut t = FdTable::new();
        t.insert(FileDescriptor {
            fd: 10,
            caps: FILE_READABLE | FILE_WRITABLE | FILE_REGULAR,
            size: 4096,
            position: 0,
            fs_id: 1,
            in_use: true,
        })
        .unwrap();
        let r = do_copy_file_range(&mut t, 10, Some(0), 10, Some(200), 100, 0).unwrap();
        assert_eq!(r.bytes_copied, 100);
    }

    #[test]
    fn cross_fs_copy_works() {
        let mut t = make_table();
        let r = do_copy_file_range_cross_fs(&mut t, 3, Some(0), 4, Some(0), 1024).unwrap();
        assert_eq!(r.bytes_copied, 1024);
    }

    #[test]
    fn copy_flags_valid() {
        assert!(CopyFlags::from_raw(0).is_ok());
        assert_eq!(CopyFlags::from_raw(0).unwrap().bits(), 0);
    }

    #[test]
    fn copy_flags_nonzero_rejected() {
        assert!(CopyFlags::from_raw(1).is_err());
        assert!(CopyFlags::from_raw(0xFFFF).is_err());
    }

    #[test]
    fn copy_range_same_fs() {
        let t = make_table();
        let range = CopyRange::from_raw(&t, 3, Some(0), 4, Some(0), 100).unwrap();
        assert!(range.same_fs(&t));
    }

    #[test]
    fn copy_range_different_fs() {
        let mut t = make_table();
        t.insert(FileDescriptor {
            fd: 8,
            caps: FILE_WRITABLE | FILE_REGULAR,
            size: 0,
            position: 0,
            fs_id: 99,
            in_use: true,
        })
        .unwrap();
        let range = CopyRange::from_raw(&t, 3, Some(0), 8, Some(0), 100).unwrap();
        assert!(!range.same_fs(&t));
    }

    #[test]
    fn copy_range_explicit_flags() {
        let t = make_table();
        let range = CopyRange::from_raw(&t, 3, Some(10), 4, None, 50).unwrap();
        assert!(range.off_in_explicit);
        assert!(!range.off_out_explicit);
    }

    #[test]
    fn copy_result_has_data() {
        let r = CopyResult {
            bytes_copied: 100,
            new_off_in: 100,
            new_off_out: 100,
            server_side: false,
            reflink: false,
        };
        assert!(r.has_data());
        assert!(!r.is_short(100));
        assert!(r.is_short(200));
    }

    #[test]
    fn copy_result_zero_bytes() {
        let r = CopyResult {
            bytes_copied: 0,
            new_off_in: 0,
            new_off_out: 0,
            server_side: false,
            reflink: false,
        };
        assert!(!r.has_data());
    }

    #[test]
    fn batched_copy_full() {
        let mut t = make_table();
        let total = copy_file_range_batched(&mut t, 3, 0, 4, 0, 4096).unwrap();
        assert_eq!(total, 4096);
    }

    #[test]
    fn batched_copy_partial() {
        let mut t = make_table();
        // Source only has 4096 bytes, ask for 10 MiB.
        let total = copy_file_range_batched(&mut t, 3, 0, 4, 0, 10 * 1024 * 1024).unwrap();
        assert_eq!(total, 4096);
    }

    #[test]
    fn batched_copy_zero_len_rejected() {
        let mut t = make_table();
        assert!(copy_file_range_batched(&mut t, 3, 0, 4, 0, 0).is_err());
    }

    #[test]
    fn copy_supports_server_copy() {
        let mut t = FdTable::new();
        t.insert(FileDescriptor {
            fd: 20,
            caps: FILE_READABLE | FILE_REGULAR | FILE_SUPPORTS_COPY,
            size: 1000,
            position: 0,
            fs_id: 1,
            in_use: true,
        })
        .unwrap();
        t.insert(FileDescriptor {
            fd: 21,
            caps: FILE_WRITABLE | FILE_REGULAR,
            size: 0,
            position: 0,
            fs_id: 1,
            in_use: true,
        })
        .unwrap();
        let range = CopyRange::from_raw(&t, 20, Some(0), 21, Some(0), 100).unwrap();
        assert!(range.supports_server_copy(&t));
    }

    #[test]
    fn fd_table_insert_remove() {
        let mut t = FdTable::new();
        t.insert(FileDescriptor {
            fd: 1,
            caps: FILE_READABLE,
            size: 0,
            position: 0,
            fs_id: 0,
            in_use: true,
        })
        .unwrap();
        assert_eq!(t.count(), 1);
        t.remove(1);
        assert_eq!(t.count(), 0);
        assert!(t.find(1).is_none());
    }
}
