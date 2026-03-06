// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `statx(2)` syscall handler.
//!
//! Implements the extended file status query interface that supersedes
//! `stat`, `lstat`, and `fstat`.  Callers specify which fields they
//! need via a bitmask so the kernel can skip expensive lookups for
//! unused metadata.
//!
//! Reference: Linux `statx(2)`, POSIX.1-2024 extended stat semantics.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// StatxMask — requested-field bitmask
// ---------------------------------------------------------------------------

/// Bitmask flags indicating which `Statx` fields were requested or
/// are valid in the response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatxMask(u32);

impl StatxMask {
    /// File type (e.g. regular, directory, symlink).
    pub const TYPE: Self = Self(0x0001);
    /// File mode (permission bits).
    pub const MODE: Self = Self(0x0002);
    /// Number of hard links.
    pub const NLINK: Self = Self(0x0004);
    /// Owner user ID.
    pub const UID: Self = Self(0x0008);
    /// Owner group ID.
    pub const GID: Self = Self(0x0010);
    /// Last access time.
    pub const ATIME: Self = Self(0x0020);
    /// Last data modification time.
    pub const MTIME: Self = Self(0x0040);
    /// Last status change time.
    pub const CTIME: Self = Self(0x0080);
    /// Inode number.
    pub const INO: Self = Self(0x0100);
    /// Total size in bytes.
    pub const SIZE: Self = Self(0x0200);
    /// Number of 512-byte blocks allocated.
    pub const BLOCKS: Self = Self(0x0400);
    /// Birth (creation) time.
    pub const BTIME: Self = Self(0x0800);
    /// Mount ID.
    pub const MNT_ID: Self = Self(0x1000);
    /// Direct I/O alignment hints.
    pub const DIOALIGN: Self = Self(0x2000);

    /// All basic stat fields (equivalent to `struct stat` coverage).
    pub const BASIC_STATS: Self = Self(
        0x0001
            | 0x0002
            | 0x0004
            | 0x0008
            | 0x0010
            | 0x0020
            | 0x0040
            | 0x0080
            | 0x0100
            | 0x0200
            | 0x0400,
    );

    /// All known fields.
    pub const ALL: Self = Self(
        0x0001
            | 0x0002
            | 0x0004
            | 0x0008
            | 0x0010
            | 0x0020
            | 0x0040
            | 0x0080
            | 0x0100
            | 0x0200
            | 0x0400
            | 0x0800
            | 0x1000
            | 0x2000,
    );

    /// Create a `StatxMask` from a raw `u32` value.
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Return the raw `u32` value.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Test whether a specific field flag is set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

// ---------------------------------------------------------------------------
// AT_* flag constants (for statx)
// ---------------------------------------------------------------------------

/// Special `dirfd` value meaning "use the current working directory".
pub const AT_FDCWD: i32 = -100;

/// If the pathname is empty, operate on the fd directly.
pub const AT_EMPTY_PATH: u32 = 0x1000;

/// Do not follow symbolic links.
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x0100;

/// Do not automount the terminal component.
pub const AT_NO_AUTOMOUNT: u32 = 0x0800;

/// Force sync of attributes from the backing store.
pub const AT_STATX_FORCE_SYNC: u32 = 0x2000;

/// Do not sync — use whatever is cached.
pub const AT_STATX_DONT_SYNC: u32 = 0x4000;

/// Mask of all valid `statx` flags.
const STATX_FLAGS_ALL: u32 = AT_EMPTY_PATH
    | AT_SYMLINK_NOFOLLOW
    | AT_NO_AUTOMOUNT
    | AT_STATX_FORCE_SYNC
    | AT_STATX_DONT_SYNC;

// ---------------------------------------------------------------------------
// StatxTimestamp
// ---------------------------------------------------------------------------

/// A high-resolution timestamp as returned by `statx`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatxTimestamp {
    /// Seconds since the epoch.
    pub tv_sec: i64,
    /// Nanoseconds (0..999_999_999).
    pub tv_nsec: u32,
    /// Reserved padding (must be zero).
    pub pad: i32,
}

// ---------------------------------------------------------------------------
// Statx — the result structure
// ---------------------------------------------------------------------------

/// Extended file status information returned by the `statx` syscall.
///
/// Only fields whose corresponding bits are set in `stx_mask` contain
/// valid data.  The remaining fields are zeroed but should not be
/// relied upon.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Statx {
    /// Bitmask of fields that are filled in (subset of the requested mask).
    pub stx_mask: u32,
    /// Preferred I/O block size.
    pub stx_blksize: u32,
    /// File attributes (immutable, append-only, etc.).
    pub stx_attributes: u64,
    /// Number of hard links.
    pub stx_nlink: u32,
    /// Owner user ID.
    pub stx_uid: u32,
    /// Owner group ID.
    pub stx_gid: u32,
    /// File mode (type + permission bits).
    pub stx_mode: u16,
    /// Padding for alignment.
    _pad0: u16,
    /// Inode number.
    pub stx_ino: u64,
    /// Total size in bytes.
    pub stx_size: u64,
    /// Number of 512-byte blocks allocated.
    pub stx_blocks: u64,
    /// Mask of supported attributes (for `stx_attributes`).
    pub stx_attributes_mask: u64,
    /// Last access time.
    pub stx_atime: StatxTimestamp,
    /// Birth (creation) time.
    pub stx_btime: StatxTimestamp,
    /// Last status change time.
    pub stx_ctime: StatxTimestamp,
    /// Last data modification time.
    pub stx_mtime: StatxTimestamp,
    /// Major device number of the device containing the file.
    pub stx_rdev_major: u32,
    /// Minor device number of the device containing the file.
    pub stx_rdev_minor: u32,
    /// Major device number of the file system.
    pub stx_dev_major: u32,
    /// Minor device number of the file system.
    pub stx_dev_minor: u32,
    /// Mount ID.
    pub stx_mnt_id: u64,
    /// Memory alignment for direct I/O.
    pub stx_dio_mem_align: u32,
    /// Offset alignment for direct I/O.
    pub stx_dio_offset_align: u32,
}

// ---------------------------------------------------------------------------
// StatxArgs — repr(C) argument block
// ---------------------------------------------------------------------------

/// Arguments for the `statx` system call.
///
/// Packed as `repr(C)` so it can be copied directly from user space
/// via `copy_from_user`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StatxArgs {
    /// Directory file descriptor (or [`AT_FDCWD`]).
    pub dirfd: i32,
    /// User-space pointer to the pathname string.
    pub pathname_ptr: u64,
    /// Flags bitmask (`AT_*` constants).
    pub flags: u32,
    /// Bitmask of fields to fill in (see [`StatxMask`]).
    pub mask: u32,
}

impl Default for StatxArgs {
    fn default() -> Self {
        Self {
            dirfd: AT_FDCWD,
            pathname_ptr: 0,
            flags: 0,
            mask: StatxMask::BASIC_STATS.bits(),
        }
    }
}

// ---------------------------------------------------------------------------
// Flag validation
// ---------------------------------------------------------------------------

/// Validate `statx` flags.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown flag bits, or both
///   `AT_STATX_FORCE_SYNC` and `AT_STATX_DONT_SYNC` specified.
fn validate_statx_flags(flags: u32) -> Result<()> {
    if flags & !STATX_FLAGS_ALL != 0 {
        return Err(Error::InvalidArgument);
    }

    // FORCE_SYNC and DONT_SYNC are mutually exclusive.
    if flags & AT_STATX_FORCE_SYNC != 0 && flags & AT_STATX_DONT_SYNC != 0 {
        return Err(Error::InvalidArgument);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// do_statx — main syscall handler
// ---------------------------------------------------------------------------

/// `statx` — get extended file status information.
///
/// Resolves the pathname relative to `dirfd`, looks up the inode, and
/// fills the requested fields of a [`Statx`] structure.  Only fields
/// whose bits are set in `args.mask` are populated; the returned
/// `stx_mask` indicates which fields the kernel was able to fill.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — invalid flags (see
///   [`validate_statx_flags`]), or a null pathname without
///   `AT_EMPTY_PATH`.
/// - [`Error::NotFound`] — the resolved path does not exist.
pub fn do_statx(args: &StatxArgs) -> Result<Statx> {
    validate_statx_flags(args.flags)?;

    // pathname_ptr must be non-null unless AT_EMPTY_PATH is set.
    if args.flags & AT_EMPTY_PATH == 0 && args.pathname_ptr == 0 {
        return Err(Error::InvalidArgument);
    }

    let requested = StatxMask::from_raw(args.mask);

    // Stub: in a real kernel we would:
    // 1. copy_from_user the pathname bytes.
    // 2. Resolve the path via resolve_at(dirfd, pathname, flags).
    // 3. Look up the inode in the VFS.
    // 4. Populate the Statx struct from inode metadata.

    let mut result = Statx::default();
    let mut filled: u32 = 0;

    // Populate fields that were requested.  All values are stubs.
    if requested.contains(StatxMask::TYPE) || requested.contains(StatxMask::MODE) {
        result.stx_mode = 0o100644; // regular file, rw-r--r--
        filled |= StatxMask::TYPE.bits() | StatxMask::MODE.bits();
    }

    if requested.contains(StatxMask::NLINK) {
        result.stx_nlink = 1;
        filled |= StatxMask::NLINK.bits();
    }

    if requested.contains(StatxMask::UID) {
        result.stx_uid = 0;
        filled |= StatxMask::UID.bits();
    }

    if requested.contains(StatxMask::GID) {
        result.stx_gid = 0;
        filled |= StatxMask::GID.bits();
    }

    if requested.contains(StatxMask::INO) {
        result.stx_ino = 0;
        filled |= StatxMask::INO.bits();
    }

    if requested.contains(StatxMask::SIZE) {
        result.stx_size = 0;
        filled |= StatxMask::SIZE.bits();
    }

    if requested.contains(StatxMask::BLOCKS) {
        result.stx_blocks = 0;
        filled |= StatxMask::BLOCKS.bits();
    }

    if requested.contains(StatxMask::ATIME) {
        result.stx_atime = StatxTimestamp::default();
        filled |= StatxMask::ATIME.bits();
    }

    if requested.contains(StatxMask::MTIME) {
        result.stx_mtime = StatxTimestamp::default();
        filled |= StatxMask::MTIME.bits();
    }

    if requested.contains(StatxMask::CTIME) {
        result.stx_ctime = StatxTimestamp::default();
        filled |= StatxMask::CTIME.bits();
    }

    if requested.contains(StatxMask::BTIME) {
        result.stx_btime = StatxTimestamp::default();
        filled |= StatxMask::BTIME.bits();
    }

    if requested.contains(StatxMask::MNT_ID) {
        result.stx_mnt_id = 0;
        filled |= StatxMask::MNT_ID.bits();
    }

    if requested.contains(StatxMask::DIOALIGN) {
        result.stx_dio_mem_align = 512;
        result.stx_dio_offset_align = 512;
        filled |= StatxMask::DIOALIGN.bits();
    }

    result.stx_mask = filled;
    result.stx_blksize = 4096;

    Ok(result)
}
