// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! File-backed `mmap` syscall handler.
//!
//! Implements file-backed `mmap(2)` per POSIX.1-2024.
//! Unlike anonymous mappings, file-backed mappings require a valid file
//! descriptor and an aligned offset. MAP_SHARED causes changes to be
//! reflected in the underlying file; MAP_PRIVATE gives copy-on-write.
//!
//! # References
//!
//! - POSIX.1-2024: `mmap()`
//! - Linux man pages: `mmap(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Page size
// ---------------------------------------------------------------------------

/// Default system page size (4 KiB).
pub const PAGE_SIZE: u64 = 4096;

/// Page mask (low PAGE_SIZE bits must be zero for alignment).
const PAGE_MASK: u64 = PAGE_SIZE - 1;

// ---------------------------------------------------------------------------
// Protection flags (PROT_*)
// ---------------------------------------------------------------------------

/// Pages may not be accessed.
pub const PROT_NONE: u32 = 0x0;
/// Pages may be read.
pub const PROT_READ: u32 = 0x1;
/// Pages may be written.
pub const PROT_WRITE: u32 = 0x2;
/// Pages may be executed.
pub const PROT_EXEC: u32 = 0x4;

/// Mask of all valid protection bits.
const PROT_VALID: u32 = PROT_READ | PROT_WRITE | PROT_EXEC;

// ---------------------------------------------------------------------------
// Map flags (MAP_*)
// ---------------------------------------------------------------------------

/// Mapping changes are shared with other processes.
pub const MAP_SHARED: u32 = 0x01;
/// Mapping is private (copy-on-write).
pub const MAP_PRIVATE: u32 = 0x02;
/// Place the mapping at exactly the specified address.
pub const MAP_FIXED: u32 = 0x10;
/// Populate page tables eagerly (prefault).
pub const MAP_POPULATE: u32 = 0x8000;
/// Do not reserve swap space.
pub const MAP_NORESERVE: u32 = 0x4000;

/// Mask of flags applicable to file-backed mappings.
const MAP_FILE_VALID: u32 = MAP_SHARED | MAP_PRIVATE | MAP_FIXED | MAP_POPULATE | MAP_NORESERVE;

// ---------------------------------------------------------------------------
// MmapFileArgs — parameter bundle
// ---------------------------------------------------------------------------

/// Arguments for a file-backed `mmap` call.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MmapFileArgs {
    /// Desired mapping address (0 means kernel chooses).
    pub addr: u64,
    /// Length of the mapping in bytes (must be non-zero).
    pub length: u64,
    /// Memory protection flags (`PROT_*`).
    pub prot: u32,
    /// Mapping flags (`MAP_SHARED` or `MAP_PRIVATE` required).
    pub flags: u32,
    /// File descriptor (must be non-negative and open for reading).
    pub fd: i32,
    /// Byte offset into the file (must be page-aligned).
    pub offset: u64,
}

impl MmapFileArgs {
    /// Validate all fields of the file-backed mmap argument bundle.
    ///
    /// Enforces:
    /// - `length` is non-zero.
    /// - Only recognised `PROT_*` bits are set.
    /// - Exactly one of `MAP_SHARED` or `MAP_PRIVATE` is set.
    /// - Only recognised `MAP_*` bits are set.
    /// - `fd` is non-negative.
    /// - `offset` is page-aligned.
    /// - For `MAP_FIXED`, `addr` is page-aligned.
    pub fn validate(&self) -> Result<()> {
        if self.length == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.prot != PROT_NONE && (self.prot & !PROT_VALID) != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.flags & !MAP_FILE_VALID != 0 {
            return Err(Error::InvalidArgument);
        }
        let shared = self.flags & MAP_SHARED != 0;
        let private = self.flags & MAP_PRIVATE != 0;
        if shared == private {
            return Err(Error::InvalidArgument);
        }
        if self.fd < 0 {
            return Err(Error::InvalidArgument);
        }
        if self.offset & PAGE_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.flags & MAP_FIXED != 0 && self.addr & PAGE_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Return `true` if the mapping is MAP_SHARED.
    pub const fn is_shared(&self) -> bool {
        self.flags & MAP_SHARED != 0
    }

    /// Return `true` if MAP_FIXED is set.
    pub const fn is_fixed(&self) -> bool {
        self.flags & MAP_FIXED != 0
    }

    /// Return the page-aligned length.
    pub fn aligned_length(&self) -> Option<u64> {
        let aligned = self.length.checked_add(PAGE_SIZE - 1)? & !PAGE_MASK;
        if aligned == 0 { None } else { Some(aligned) }
    }
}

// ---------------------------------------------------------------------------
// FileMetadata — simulated file information
// ---------------------------------------------------------------------------

/// Metadata about the file being mapped.
#[derive(Debug, Clone, Copy, Default)]
pub struct FileMetadata {
    /// Total file size in bytes.
    pub file_size: u64,
    /// Whether the file was opened with write access.
    pub writable: bool,
    /// Whether the file is executable.
    pub executable: bool,
}

impl FileMetadata {
    /// Create metadata for a file.
    pub const fn new(file_size: u64, writable: bool, executable: bool) -> Self {
        Self {
            file_size,
            writable,
            executable,
        }
    }

    /// Validate that the mapping can be created given the file metadata.
    ///
    /// - `MAP_SHARED | PROT_WRITE` requires the file to be writable.
    /// - The offset + length must not exceed the file size.
    pub fn validate_mapping(&self, args: &MmapFileArgs) -> Result<()> {
        // MAP_SHARED + PROT_WRITE requires write access to the file.
        if args.is_shared() && args.prot & PROT_WRITE != 0 && !self.writable {
            return Err(Error::PermissionDenied);
        }
        // Mapping must not extend beyond the file.
        let end = args
            .offset
            .checked_add(args.length)
            .ok_or(Error::InvalidArgument)?;
        if end > self.file_size && !self.is_zero_sized() {
            // Allow mapping beyond EOF — the excess pages are zero-filled
            // (Linux semantics). Only reject if offset itself is past EOF.
            if args.offset >= self.file_size {
                return Err(Error::InvalidArgument);
            }
        }
        Ok(())
    }

    fn is_zero_sized(&self) -> bool {
        self.file_size == 0
    }
}

// ---------------------------------------------------------------------------
// MmapResult — outcome
// ---------------------------------------------------------------------------

/// Result of a successful file-backed mmap.
#[derive(Debug, Clone, Copy, Default)]
pub struct MmapResult {
    /// Base address of the new mapping.
    pub addr: u64,
    /// Actual length of the mapping (page-aligned).
    pub length: u64,
    /// File descriptor backing the mapping.
    pub fd: i32,
    /// Byte offset in the file.
    pub offset: u64,
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Return `true` if `addr` is page-aligned (or zero).
fn is_page_aligned(addr: u64) -> bool {
    addr & PAGE_MASK == 0
}

// ---------------------------------------------------------------------------
// Public syscall handlers
// ---------------------------------------------------------------------------

/// `mmap` (file-backed) — map a file into the process address space.
///
/// Creates a mapping of `args.length` bytes from `args.fd` starting at
/// `args.offset`. The `file_meta` parameter provides size and permission
/// information for the underlying file.
///
/// If `args.addr == 0`, the kernel selects an appropriate address
/// (stub: returns a fixed placeholder). For `MAP_FIXED`, the mapping
/// is placed at exactly `args.addr`.
///
/// Returns the base address of the mapping on success.
///
/// # Errors
///
/// | `Error`           | Condition                                         |
/// |-------------------|---------------------------------------------------|
/// | `InvalidArgument` | Any field fails validation                        |
/// | `PermissionDenied`| `MAP_SHARED | PROT_WRITE` on a read-only file     |
///
/// Reference: POSIX.1-2024 §mmap.
pub fn do_mmap_file(args: &MmapFileArgs, file_meta: &FileMetadata) -> Result<MmapResult> {
    args.validate()?;
    file_meta.validate_mapping(args)?;

    let aligned_len = args.aligned_length().ok_or(Error::InvalidArgument)?;

    let base_addr = if args.is_fixed() {
        args.addr
    } else if args.addr != 0 && is_page_aligned(args.addr) {
        // Hint provided: try to use it; stub ignores and returns placeholder.
        0x0000_7FFF_0000_0000u64
    } else {
        // Kernel-chosen address (stub placeholder).
        0x0000_7FFF_0000_0000u64
    };

    let _ = aligned_len;

    // Stub: real implementation inserts a VMA into the process mm_struct
    // and sets up page table entries for the file mapping.
    Ok(MmapResult {
        addr: base_addr,
        length: aligned_len,
        fd: args.fd,
        offset: args.offset,
    })
}

/// Validate file-backed mmap arguments without creating the mapping.
pub fn validate_mmap_file_args(args: &MmapFileArgs, file_meta: &FileMetadata) -> Result<()> {
    args.validate()?;
    file_meta.validate_mapping(args)
}

/// Compute the page-aligned length for a given mmap length.
///
/// Returns `Err(InvalidArgument)` if `length` is zero or would overflow.
pub fn mmap_aligned_length(length: u64) -> Result<u64> {
    if length == 0 {
        return Err(Error::InvalidArgument);
    }
    let aligned = length
        .checked_add(PAGE_SIZE - 1)
        .ok_or(Error::InvalidArgument)?
        & !PAGE_MASK;
    if aligned == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(aligned)
}
