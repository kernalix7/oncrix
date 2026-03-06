// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX mmap-family syscall handlers.
//!
//! Implements `mmap`, `munmap`, `mprotect`, `mremap`, `madvise`, and `brk`
//! per POSIX.1-2024 (IEEE Std 1003.1-2024).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Page size constant
// ---------------------------------------------------------------------------

/// Default page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Page-offset mask (low 12 bits).
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
const PROT_VALID_MASK: u32 = PROT_READ | PROT_WRITE | PROT_EXEC;

// ---------------------------------------------------------------------------
// Map flags (MAP_*)
// ---------------------------------------------------------------------------

/// Share changes with other processes.
pub const MAP_SHARED: u32 = 0x01;
/// Changes are private (copy-on-write).
pub const MAP_PRIVATE: u32 = 0x02;
/// Place mapping at exactly the specified address.
pub const MAP_FIXED: u32 = 0x10;
/// Mapping is not backed by any file (zero-filled).
pub const MAP_ANONYMOUS: u32 = 0x20;
/// Mapping is suitable for a stack.
pub const MAP_STACK: u32 = 0x20000;
/// Create a huge-page mapping.
pub const MAP_HUGETLB: u32 = 0x40000;
/// Prefault page tables for the mapping.
pub const MAP_POPULATE: u32 = 0x8000;
/// Do not reserve swap space for the mapping.
pub const MAP_NORESERVE: u32 = 0x4000;

/// Mask of all recognised map flags.
const MAP_VALID_MASK: u32 = MAP_SHARED
    | MAP_PRIVATE
    | MAP_FIXED
    | MAP_ANONYMOUS
    | MAP_STACK
    | MAP_HUGETLB
    | MAP_POPULATE
    | MAP_NORESERVE;

// ---------------------------------------------------------------------------
// Madvise advice values (MADV_*)
// ---------------------------------------------------------------------------

/// No special treatment (default).
pub const MADV_NORMAL: i32 = 0;
/// Expect random page references.
pub const MADV_RANDOM: i32 = 1;
/// Expect sequential page references.
pub const MADV_SEQUENTIAL: i32 = 2;
/// Will need these pages soon.
pub const MADV_WILLNEED: i32 = 3;
/// Do not need these pages.
pub const MADV_DONTNEED: i32 = 4;
/// Free pages without swapping out.
pub const MADV_FREE: i32 = 8;
/// Mark region as eligible for KSM (Kernel Same-page Merging).
pub const MADV_MERGEABLE: i32 = 12;
/// Mark region as ineligible for KSM.
pub const MADV_UNMERGEABLE: i32 = 13;
/// Enable transparent huge pages for this region.
pub const MADV_HUGEPAGE: i32 = 14;
/// Disable transparent huge pages for this region.
pub const MADV_NOHUGEPAGE: i32 = 15;

// ---------------------------------------------------------------------------
// Mremap flags (MREMAP_*)
// ---------------------------------------------------------------------------

/// Allow the kernel to relocate the mapping.
pub const MREMAP_MAYMOVE: u32 = 1;
/// Move mapping to a new fixed address.
pub const MREMAP_FIXED: u32 = 2;

/// Mask of all recognised mremap flags.
const MREMAP_VALID_MASK: u32 = MREMAP_MAYMOVE | MREMAP_FIXED;

// ---------------------------------------------------------------------------
// Default program break for brk(2).
// ---------------------------------------------------------------------------

/// Initial program break (arbitrary user-space address).
const DEFAULT_BRK: u64 = 0x0000_4000_0000_0000;

// ---------------------------------------------------------------------------
// MmapArgs — parameter bundle for mmap(2)
// ---------------------------------------------------------------------------

/// Arguments for the `mmap(2)` system call.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MmapArgs {
    /// Desired mapping address (0 = kernel chooses).
    pub addr: u64,
    /// Requested mapping length in bytes.
    pub length: u64,
    /// Protection flags (`PROT_*`).
    pub prot: u32,
    /// Mapping flags (`MAP_*`).
    pub flags: u32,
    /// File descriptor (ignored for anonymous mappings).
    pub fd: i32,
    /// Offset into the file (must be page-aligned).
    pub offset: u64,
}

impl MmapArgs {
    /// Validate all fields of the mmap argument bundle.
    ///
    /// Checks:
    /// - `length` is non-zero.
    /// - Only recognised protection and map flag bits are set.
    /// - Exactly one of `MAP_SHARED` or `MAP_PRIVATE` is set.
    /// - For `MAP_FIXED`, `addr` is page-aligned.
    /// - `offset` is page-aligned.
    /// - Anonymous mappings have `fd == -1`.
    pub fn validate(&self) -> Result<()> {
        // Length must be non-zero.
        if self.length == 0 {
            return Err(Error::InvalidArgument);
        }

        // Only valid prot bits.
        if self.prot & !PROT_VALID_MASK != 0 && self.prot != PROT_NONE {
            return Err(Error::InvalidArgument);
        }

        // Only recognised flags.
        if self.flags & !MAP_VALID_MASK != 0 {
            return Err(Error::InvalidArgument);
        }

        // Exactly one of SHARED / PRIVATE.
        let shared = self.flags & MAP_SHARED != 0;
        let private = self.flags & MAP_PRIVATE != 0;
        if shared == private {
            return Err(Error::InvalidArgument);
        }

        // MAP_FIXED requires page-aligned addr.
        if self.is_fixed() && (self.addr & PAGE_MASK) != 0 {
            return Err(Error::InvalidArgument);
        }

        // Offset must be page-aligned.
        if (self.offset & PAGE_MASK) != 0 {
            return Err(Error::InvalidArgument);
        }

        // Anonymous mappings should use fd == -1.
        if self.is_anonymous() && self.fd != -1 {
            return Err(Error::InvalidArgument);
        }

        Ok(())
    }

    /// Return `true` if this is an anonymous (non-file-backed) mapping.
    pub fn is_anonymous(&self) -> bool {
        self.flags & MAP_ANONYMOUS != 0
    }

    /// Return `true` if this is a private (copy-on-write) mapping.
    pub fn is_private(&self) -> bool {
        self.flags & MAP_PRIVATE != 0
    }

    /// Return `true` if the mapping must be placed at exactly `addr`.
    pub fn is_fixed(&self) -> bool {
        self.flags & MAP_FIXED != 0
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Return `true` if the address is page-aligned.
fn is_page_aligned(addr: u64) -> bool {
    addr & PAGE_MASK == 0
}

/// Align `size` up to the next page boundary.
fn page_align_up(size: u64) -> u64 {
    (size.wrapping_add(PAGE_SIZE - 1)) & !PAGE_MASK
}

/// Validate that a protection value contains only known bits.
fn validate_prot(prot: u32) -> Result<()> {
    if prot != PROT_NONE && (prot & !PROT_VALID_MASK) != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate that an `madvise` advice value is recognised.
fn validate_advice(advice: i32) -> Result<()> {
    match advice {
        MADV_NORMAL | MADV_RANDOM | MADV_SEQUENTIAL | MADV_WILLNEED | MADV_DONTNEED | MADV_FREE
        | MADV_MERGEABLE | MADV_UNMERGEABLE | MADV_HUGEPAGE | MADV_NOHUGEPAGE => Ok(()),
        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// Syscall handlers
// ---------------------------------------------------------------------------

/// `mmap` — map memory into the process address space.
///
/// Validates `args`, page-aligns `length`, and returns the base address
/// of the new mapping on success. Anonymous mappings are zero-filled;
/// file-backed mappings are not yet supported.
///
/// Reference: POSIX.1-2024 §mmap.
pub fn do_mmap(args: &MmapArgs) -> Result<u64> {
    args.validate()?;

    let aligned_len = page_align_up(args.length);
    if aligned_len == 0 {
        // Overflow during alignment.
        return Err(Error::InvalidArgument);
    }

    // File-backed mappings are not yet implemented.
    if !args.is_anonymous() {
        return Err(Error::NotImplemented);
    }

    let _ = aligned_len;

    // Stub: real implementation delegates to oncrix_kernel::mmap::do_mmap.
    Err(Error::NotImplemented)
}

/// `munmap` — unmap a memory region.
///
/// Both `addr` and `length` must satisfy alignment requirements:
/// `addr` must be page-aligned, `length` is rounded up to a page boundary.
///
/// Reference: POSIX.1-2024 §munmap.
pub fn do_munmap(addr: u64, length: u64) -> Result<()> {
    if !is_page_aligned(addr) {
        return Err(Error::InvalidArgument);
    }
    if length == 0 {
        return Err(Error::InvalidArgument);
    }

    let aligned_len = page_align_up(length);
    if aligned_len == 0 {
        return Err(Error::InvalidArgument);
    }

    let _ = aligned_len;

    // Stub: real implementation removes page table entries and frees frames.
    Err(Error::NotImplemented)
}

/// `mprotect` — change protection of a memory region.
///
/// `addr` must be page-aligned and `prot` must contain only valid
/// `PROT_*` bits. `length` is rounded up to a page boundary.
///
/// Reference: POSIX.1-2024 §mprotect.
pub fn do_mprotect(addr: u64, length: u64, prot: u32) -> Result<()> {
    if !is_page_aligned(addr) {
        return Err(Error::InvalidArgument);
    }
    if length == 0 {
        return Err(Error::InvalidArgument);
    }

    validate_prot(prot)?;

    let aligned_len = page_align_up(length);
    if aligned_len == 0 {
        return Err(Error::InvalidArgument);
    }

    let _ = aligned_len;

    // Stub: real implementation updates page table protection bits.
    Err(Error::NotImplemented)
}

/// `mremap` — resize or relocate a memory mapping.
///
/// `old_addr` must be page-aligned. `MREMAP_FIXED` requires
/// `MREMAP_MAYMOVE` to also be set. Returns the new mapping address.
///
/// Reference: Linux mremap(2) (non-POSIX extension).
pub fn do_mremap(
    old_addr: u64,
    old_size: u64,
    new_size: u64,
    flags: u32,
    new_addr: u64,
) -> Result<u64> {
    if !is_page_aligned(old_addr) {
        return Err(Error::InvalidArgument);
    }
    if old_size == 0 || new_size == 0 {
        return Err(Error::InvalidArgument);
    }

    // Only valid mremap flags.
    if flags & !MREMAP_VALID_MASK != 0 {
        return Err(Error::InvalidArgument);
    }

    // MREMAP_FIXED requires MREMAP_MAYMOVE.
    if flags & MREMAP_FIXED != 0 && flags & MREMAP_MAYMOVE == 0 {
        return Err(Error::InvalidArgument);
    }

    // If MREMAP_FIXED, new_addr must be page-aligned.
    if flags & MREMAP_FIXED != 0 && !is_page_aligned(new_addr) {
        return Err(Error::InvalidArgument);
    }

    let aligned_old = page_align_up(old_size);
    let aligned_new = page_align_up(new_size);
    if aligned_old == 0 || aligned_new == 0 {
        return Err(Error::InvalidArgument);
    }

    let _ = (aligned_old, aligned_new);

    // Stub: real implementation resizes/relocates the mapping.
    Err(Error::NotImplemented)
}

/// `madvise` — advise the kernel about memory usage patterns.
///
/// `addr` must be page-aligned and `advice` must be a recognised
/// `MADV_*` value. `length` is rounded up to a page boundary.
///
/// Reference: POSIX.1-2024 §posix_madvise, Linux madvise(2).
pub fn do_madvise(addr: u64, length: u64, advice: i32) -> Result<()> {
    if !is_page_aligned(addr) {
        return Err(Error::InvalidArgument);
    }
    if length == 0 {
        return Err(Error::InvalidArgument);
    }

    validate_advice(advice)?;

    let aligned_len = page_align_up(length);
    if aligned_len == 0 {
        return Err(Error::InvalidArgument);
    }

    let _ = aligned_len;

    // Stub: real implementation adjusts page cache behaviour.
    Err(Error::NotImplemented)
}

/// `brk` — change the program break (end of the data segment).
///
/// If `addr` is 0, returns the current program break. Otherwise,
/// sets the program break to `addr` (must be page-aligned) and
/// returns the new break on success.
///
/// Reference: Linux brk(2).
pub fn do_brk(addr: u64) -> Result<u64> {
    // addr == 0 means query the current break.
    if addr == 0 {
        return Ok(DEFAULT_BRK);
    }

    if !is_page_aligned(addr) {
        return Err(Error::InvalidArgument);
    }

    // Stub: real implementation adjusts the process heap boundary.
    Err(Error::NotImplemented)
}
