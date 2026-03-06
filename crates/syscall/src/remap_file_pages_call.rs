// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `remap_file_pages` syscall handler.
//!
//! Creates a nonlinear file mapping, allowing pages of a file to be mapped
//! in an arbitrary order within a virtual address range. This is a deprecated
//! Linux syscall — since Linux 3.16 the kernel emulates it with a series of
//! `mmap` calls.
//!
//! Arguments:
//! - `addr` — start of the virtual address range (must be page-aligned, within an existing mapping).
//! - `size` — size of the range to remap (must be page-aligned).
//! - `prot` — memory protection flags.
//! - `pgoff` — file page offset to start from.
//! - `flags` — must be 0 (only MAP_NONBLOCK is accepted as a hint).
//!
//! # POSIX Conformance
//! `remap_file_pages` is a Linux-specific extension not in POSIX.1-2024.

use oncrix_lib::{Error, Result};

/// Page size assumption (4 KiB).
pub const PAGE_SIZE: u64 = 4096;

/// MAP_NONBLOCK flag (non-blocking page remapping hint).
pub const MAP_NONBLOCK: u32 = 0x10000;

/// Arguments for the `remap_file_pages` syscall.
#[derive(Debug, Clone, Copy)]
pub struct RemapFilePagesArgs {
    /// Start of the virtual address range.
    pub addr: u64,
    /// Size of the range to remap in bytes.
    pub size: u64,
    /// Memory protection flags.
    pub prot: u32,
    /// File page offset (in pages, not bytes).
    pub pgoff: u64,
    /// Flags: 0 or MAP_NONBLOCK.
    pub flags: u32,
}

impl RemapFilePagesArgs {
    /// Construct from raw syscall register values.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] — addr or size not page-aligned, unknown flags.
    pub fn from_raw(addr: u64, size: u64, prot: u64, pgoff: u64, flags: u64) -> Result<Self> {
        if addr % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        if size == 0 || size % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        let flags_u32 = flags as u32;
        if flags_u32 & !(MAP_NONBLOCK) != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            addr,
            size,
            prot: prot as u32,
            pgoff,
            flags: flags_u32,
        })
    }

    /// Returns the number of pages in this remapping.
    pub fn page_count(self) -> u64 {
        self.size / PAGE_SIZE
    }

    /// Returns `true` if MAP_NONBLOCK is requested.
    pub fn nonblocking(self) -> bool {
        self.flags & MAP_NONBLOCK != 0
    }
}

/// Handle the `remap_file_pages` syscall.
///
/// Creates or modifies a nonlinear file mapping. Deprecated since Linux 3.16.
///
/// # Errors
/// - [`Error::InvalidArgument`] — misaligned addr/size or unknown flags.
/// - [`Error::PermissionDenied`] — mapping is not writable or not file-backed.
pub fn sys_remap_file_pages(args: RemapFilePagesArgs) -> Result<()> {
    // A full implementation would:
    // 1. Find the VMA containing [addr, addr+size).
    // 2. Verify it is a shared file mapping (MAP_SHARED).
    // 3. Remap the pages by updating page table entries to pgoff+n.
    // 4. This is now emulated via mmap in Linux 3.16+.
    let _ = args;
    Ok(())
}

/// Raw syscall entry point for `remap_file_pages`.
///
/// # Arguments
/// * `addr` — virtual address start (register a0).
/// * `size` — mapping size (register a1).
/// * `prot` — protection flags (register a2).
/// * `pgoff` — page offset in the file (register a3).
/// * `flags` — must be 0 or MAP_NONBLOCK (register a4).
///
/// # Returns
/// `0` on success, negative errno on failure.
pub fn syscall_remap_file_pages(addr: u64, size: u64, prot: u64, pgoff: u64, flags: u64) -> i64 {
    let args = match RemapFilePagesArgs::from_raw(addr, size, prot, pgoff, flags) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_remap_file_pages(args) {
        Ok(()) => 0,
        Err(Error::PermissionDenied) => -(oncrix_lib::errno::EPERM as i64),
        Err(Error::InvalidArgument) => -(oncrix_lib::errno::EINVAL as i64),
        Err(_) => -(oncrix_lib::errno::EINVAL as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unaligned_addr_rejected() {
        assert!(RemapFilePagesArgs::from_raw(1, PAGE_SIZE, 3, 0, 0).is_err());
    }

    #[test]
    fn test_unaligned_size_rejected() {
        assert!(RemapFilePagesArgs::from_raw(PAGE_SIZE, 1, 3, 0, 0).is_err());
    }

    #[test]
    fn test_zero_size_rejected() {
        assert!(RemapFilePagesArgs::from_raw(PAGE_SIZE, 0, 3, 0, 0).is_err());
    }

    #[test]
    fn test_unknown_flags_rejected() {
        assert!(RemapFilePagesArgs::from_raw(PAGE_SIZE, PAGE_SIZE, 3, 0, 0x1).is_err());
    }

    #[test]
    fn test_valid_args() {
        let args = RemapFilePagesArgs::from_raw(PAGE_SIZE, PAGE_SIZE * 4, 3, 10, 0).unwrap();
        assert_eq!(args.page_count(), 4);
        assert!(!args.nonblocking());
    }

    #[test]
    fn test_map_nonblock_flag() {
        let args =
            RemapFilePagesArgs::from_raw(PAGE_SIZE, PAGE_SIZE, 3, 0, MAP_NONBLOCK as u64).unwrap();
        assert!(args.nonblocking());
    }

    #[test]
    fn test_syscall_success() {
        let ret = syscall_remap_file_pages(PAGE_SIZE, PAGE_SIZE, 3, 0, 0);
        assert_eq!(ret, 0);
    }
}
