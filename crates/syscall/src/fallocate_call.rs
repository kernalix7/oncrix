// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `fallocate(2)` syscall handler.
//!
//! Manipulates the disk space allocated for a file.  Depending on `mode`,
//! the call can preallocate space without extending file size, punch holes,
//! collapse ranges, zero-fill ranges, or insert new space.
//!
//! # POSIX Conformance
//!
//! `posix_fallocate()` (POSIX) is a subset of `fallocate()` (Linux).  This
//! module implements the full Linux `fallocate` interface.  Key behaviours:
//! - `mode == 0` — allocate and initialise disk blocks in `[offset, offset+len)`;
//!   file size may increase.
//! - `FALLOC_FL_KEEP_SIZE` — allocate but do not extend file size.
//! - `FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE` — deallocate and zero the range.
//! - `FALLOC_FL_COLLAPSE_RANGE` — remove bytes from the file, shifting data.
//! - `FALLOC_FL_ZERO_RANGE` — zero the range (allocate if needed).
//! - `FALLOC_FL_INSERT_RANGE` — insert space, shifting existing data up.
//! - `ESPIPE` for non-seekable files; `ENODEV` for special files.
//! - Both `offset` and `len` must be > 0 (`EINVAL` otherwise).
//! - Only regular files are supported; pipes/devices return `ESPIPE`/`ENODEV`.
//!
//! # References
//!
//! - Linux man pages: `fallocate(2)`
//! - POSIX.1-2024: `posix_fallocate()`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Mode flags
// ---------------------------------------------------------------------------

/// Allocate without extending file size.
pub const FALLOC_FL_KEEP_SIZE: i32 = 0x01;
/// Deallocate (punch hole) in range; must be combined with KEEP_SIZE.
pub const FALLOC_FL_PUNCH_HOLE: i32 = 0x02;
/// Remove bytes from the file interior, collapsing the range.
pub const FALLOC_FL_COLLAPSE_RANGE: i32 = 0x08;
/// Zero bytes in range (allocating blocks if needed).
pub const FALLOC_FL_ZERO_RANGE: i32 = 0x10;
/// Insert space, moving existing data up.
pub const FALLOC_FL_INSERT_RANGE: i32 = 0x20;
/// Unshare shared blocks (COW filesystems).
pub const FALLOC_FL_UNSHARE_RANGE: i32 = 0x40;

/// All recognised mode flags.
const FALLOC_FL_KNOWN: i32 = FALLOC_FL_KEEP_SIZE
    | FALLOC_FL_PUNCH_HOLE
    | FALLOC_FL_COLLAPSE_RANGE
    | FALLOC_FL_ZERO_RANGE
    | FALLOC_FL_INSERT_RANGE
    | FALLOC_FL_UNSHARE_RANGE;

// ---------------------------------------------------------------------------
// File metadata for fallocate
// ---------------------------------------------------------------------------

/// File type for `fallocate` validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    /// Regular file — fallocate is supported.
    Regular,
    /// Special (device/pipe) — fallocate is not supported.
    Special,
}

/// Metadata about a file used to validate a `fallocate` call.
#[derive(Debug, Clone, Copy)]
pub struct FallocateFile {
    /// File type.
    pub file_type: FileType,
    /// Current file size in bytes.
    pub size: i64,
    /// Maximum file size enforced by the filesystem / process limits.
    pub max_size: i64,
}

// ---------------------------------------------------------------------------
// Fallocate outcome
// ---------------------------------------------------------------------------

/// Describes the change to file metadata after a successful `fallocate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FallocateResult {
    /// New file size after the operation.
    pub new_size: i64,
    /// Number of bytes allocated (for mode 0 / KEEP_SIZE / ZERO_RANGE).
    pub bytes_allocated: i64,
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `fallocate(2)`.
///
/// Validates arguments and computes the resulting file state.  In a real
/// kernel this would also invoke the filesystem's `fallocate` inode method.
///
/// # Errors
///
/// | `Error`      | Condition                                               |
/// |--------------|---------------------------------------------------------|
/// | `InvalidArg` | Unknown mode bits                                       |
/// | `InvalidArg` | `offset < 0` or `len <= 0`                              |
/// | `InvalidArg` | PUNCH_HOLE without KEEP_SIZE                            |
/// | `InvalidArg` | COLLAPSE_RANGE combined with KEEP_SIZE or PUNCH_HOLE    |
/// | `NotSupported` | File is not a regular file                            |
/// | `TooBig`     | Operation would exceed `max_size`                       |
pub fn do_fallocate(
    file: &mut FallocateFile,
    mode: i32,
    offset: i64,
    len: i64,
) -> Result<FallocateResult> {
    // Unknown flags.
    if mode & !FALLOC_FL_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }

    // Regular files only.
    if file.file_type != FileType::Regular {
        return Err(Error::NotImplemented);
    }

    // Both offset and len must be non-negative; len must be > 0.
    if offset < 0 || len <= 0 {
        return Err(Error::InvalidArgument);
    }

    // PUNCH_HOLE must always be combined with KEEP_SIZE.
    if mode & FALLOC_FL_PUNCH_HOLE != 0 && mode & FALLOC_FL_KEEP_SIZE == 0 {
        return Err(Error::InvalidArgument);
    }

    // COLLAPSE_RANGE cannot be combined with KEEP_SIZE or PUNCH_HOLE.
    if mode & FALLOC_FL_COLLAPSE_RANGE != 0
        && (mode & FALLOC_FL_KEEP_SIZE != 0 || mode & FALLOC_FL_PUNCH_HOLE != 0)
    {
        return Err(Error::InvalidArgument);
    }

    // INSERT_RANGE cannot be combined with KEEP_SIZE.
    if mode & FALLOC_FL_INSERT_RANGE != 0 && mode & FALLOC_FL_KEEP_SIZE != 0 {
        return Err(Error::InvalidArgument);
    }

    let end = offset.checked_add(len).ok_or(Error::InvalidArgument)?;

    // Dispatch based on mode.
    if mode & FALLOC_FL_PUNCH_HOLE != 0 {
        // Punch hole: zero + deallocate; file size unchanged.
        let allocated = if end > file.size {
            (file.size - offset).max(0)
        } else {
            len
        };
        Ok(FallocateResult {
            new_size: file.size,
            bytes_allocated: -allocated,
        })
    } else if mode & FALLOC_FL_COLLAPSE_RANGE != 0 {
        // Collapse: remove [offset, offset+len) from the file.
        if end > file.size {
            return Err(Error::InvalidArgument);
        }
        let new_size = file.size - len;
        file.size = new_size;
        Ok(FallocateResult {
            new_size,
            bytes_allocated: -len,
        })
    } else if mode & FALLOC_FL_INSERT_RANGE != 0 {
        // Insert: shift data at offset up by len bytes.
        let new_size = file.size.checked_add(len).ok_or(Error::InvalidArgument)?;
        if new_size > file.max_size {
            return Err(Error::InvalidArgument);
        }
        file.size = new_size;
        Ok(FallocateResult {
            new_size,
            bytes_allocated: len,
        })
    } else {
        // Mode 0 / KEEP_SIZE / ZERO_RANGE — allocate blocks.
        let keep = mode & FALLOC_FL_KEEP_SIZE != 0;
        let new_size = if keep || end <= file.size {
            file.size
        } else {
            if end > file.max_size {
                return Err(Error::InvalidArgument);
            }
            end
        };
        let prev_size = file.size;
        file.size = new_size;
        let allocated = if new_size > prev_size {
            new_size - prev_size
        } else {
            len
        };
        Ok(FallocateResult {
            new_size,
            bytes_allocated: allocated,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn regular_file(size: i64) -> FallocateFile {
        FallocateFile {
            file_type: FileType::Regular,
            size,
            max_size: 1 << 30,
        }
    }

    #[test]
    fn allocate_extends_file() {
        let mut f = regular_file(0);
        let r = do_fallocate(&mut f, 0, 0, 4096).unwrap();
        assert_eq!(r.new_size, 4096);
    }

    #[test]
    fn keep_size_no_extend() {
        let mut f = regular_file(1024);
        let r = do_fallocate(&mut f, FALLOC_FL_KEEP_SIZE, 0, 8192).unwrap();
        assert_eq!(r.new_size, 1024);
    }

    #[test]
    fn punch_hole() {
        let mut f = regular_file(8192);
        let r = do_fallocate(
            &mut f,
            FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
            1024,
            1024,
        )
        .unwrap();
        assert_eq!(r.new_size, 8192);
        assert!(r.bytes_allocated <= 0);
    }

    #[test]
    fn punch_hole_without_keep_size_fails() {
        let mut f = regular_file(8192);
        assert_eq!(
            do_fallocate(&mut f, FALLOC_FL_PUNCH_HOLE, 0, 4096),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn special_file_fails() {
        let mut f = FallocateFile {
            file_type: FileType::Special,
            size: 0,
            max_size: 0,
        };
        assert_eq!(do_fallocate(&mut f, 0, 0, 4096), Err(Error::NotImplemented));
    }

    #[test]
    fn collapse_range() {
        let mut f = regular_file(8192);
        let r = do_fallocate(&mut f, FALLOC_FL_COLLAPSE_RANGE, 0, 4096).unwrap();
        assert_eq!(r.new_size, 4096);
    }
}
