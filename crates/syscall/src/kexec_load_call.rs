// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `kexec_load(2)` / `kexec_file_load(2)` syscall handlers — load a new kernel.
//!
//! `kexec_load` loads a new kernel image described by `nr_segments` memory
//! segments into the running system in preparation for a fast reboot.
//! `kexec_file_load` loads the image from an open file descriptor.
//! Both require `CAP_SYS_BOOT`.
//!
//! # Syscall signatures
//!
//! ```text
//! long kexec_load(unsigned long entry, unsigned long nr_segments,
//!                 struct kexec_segment *segments, unsigned long flags);
//!
//! long kexec_file_load(int kernel_fd, int initrd_fd,
//!                      unsigned long cmdline_len,
//!                      const char *cmdline, unsigned long flags);
//! ```
//!
//! # Flags
//!
//! | Flag | Value | Description |
//! |------|-------|-------------|
//! | `KEXEC_ON_CRASH`       | 0x1 | Load crash kernel |
//! | `KEXEC_PRESERVE_CONTEXT` | 0x2 | Preserve context across kexec |
//! | `KEXEC_FILE_UNLOAD`    | 0x1 | Unload currently loaded image |
//! | `KEXEC_FILE_ON_CRASH`  | 0x2 | Load in crash kernel region |
//! | `KEXEC_FILE_NO_INITRAMFS` | 0x4 | No initramfs |
//!
//! # References
//!
//! - Linux: `kernel/kexec.c`, `kernel/kexec_file.c`
//! - `kexec_load(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Capability required to load a new kernel image.
pub const CAP_SYS_BOOT: u32 = 22;

/// Maximum number of kexec segments per call.
pub const KEXEC_SEGMENT_MAX: usize = 16;

/// Load into the crash kernel region.
pub const KEXEC_ON_CRASH: u64 = 0x1;
/// Preserve hardware context across kexec.
pub const KEXEC_PRESERVE_CONTEXT: u64 = 0x2;

/// File-based: unload the currently loaded image.
pub const KEXEC_FILE_UNLOAD: u64 = 0x1;
/// File-based: load in the crash kernel region.
pub const KEXEC_FILE_ON_CRASH: u64 = 0x2;
/// File-based: no initramfs will be provided.
pub const KEXEC_FILE_NO_INITRAMFS: u64 = 0x4;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// A single kexec memory segment.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct KexecSegment {
    /// User-space source buffer pointer.
    pub buf: u64,
    /// Size of the source buffer.
    pub bufsz: u64,
    /// Target physical memory address.
    pub mem: u64,
    /// Size of the target memory region.
    pub memsz: u64,
}

impl KexecSegment {
    /// Create a new segment descriptor.
    pub const fn new(buf: u64, bufsz: u64, mem: u64, memsz: u64) -> Self {
        Self {
            buf,
            bufsz,
            mem,
            memsz,
        }
    }

    /// Validate that the segment is non-empty.
    pub fn is_valid(&self) -> bool {
        self.bufsz > 0 && self.memsz >= self.bufsz
    }
}

/// Parameters for a `kexec_load` call.
#[derive(Debug, Clone, Copy)]
pub struct KexecLoadRequest {
    /// Entry point in the new kernel image.
    pub entry: u64,
    /// Number of segments in the array.
    pub nr_segments: u64,
    /// User-space pointer to segment array.
    pub segments: u64,
    /// Flags controlling kexec behaviour.
    pub flags: u64,
}

impl KexecLoadRequest {
    /// Create a new request.
    pub const fn new(entry: u64, nr_segments: u64, segments: u64, flags: u64) -> Self {
        Self {
            entry,
            nr_segments,
            segments,
            flags,
        }
    }

    /// Validate the request.
    pub fn validate(&self) -> Result<()> {
        if self.nr_segments > KEXEC_SEGMENT_MAX as u64 {
            return Err(Error::InvalidArgument);
        }
        if self.nr_segments > 0 && self.segments == 0 {
            return Err(Error::InvalidArgument);
        }
        let known = KEXEC_ON_CRASH | KEXEC_PRESERVE_CONTEXT;
        if self.flags & !known != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for KexecLoadRequest {
    fn default() -> Self {
        Self::new(0, 0, 0, 0)
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handle `kexec_load(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — too many segments, null segment pointer, or
///   unknown flags.
/// - [`Error::PermissionDenied`] — caller lacks `CAP_SYS_BOOT`.
/// - [`Error::NotImplemented`] — kexec subsystem not yet wired.
pub fn sys_kexec_load(
    entry: u64,
    nr_segments: u64,
    segments: u64,
    flags: u64,
    caps: u64,
) -> Result<i64> {
    if caps & (1u64 << CAP_SYS_BOOT) == 0 {
        return Err(Error::PermissionDenied);
    }
    let req = KexecLoadRequest::new(entry, nr_segments, segments, flags);
    req.validate()?;
    do_kexec_load(&req)
}

fn do_kexec_load(req: &KexecLoadRequest) -> Result<i64> {
    let _ = req;
    // TODO: Copy segments from user space, validate memory ranges, load into
    // reserved kexec memory, and install the new kernel entry point.
    Err(Error::NotImplemented)
}

/// Handle `kexec_file_load(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — negative fd or unknown flags.
/// - [`Error::PermissionDenied`] — caller lacks `CAP_SYS_BOOT`.
/// - [`Error::NotImplemented`] — kexec subsystem not yet wired.
pub fn sys_kexec_file_load(
    kernel_fd: i32,
    initrd_fd: i32,
    cmdline_len: u64,
    cmdline: u64,
    flags: u64,
    caps: u64,
) -> Result<i64> {
    if caps & (1u64 << CAP_SYS_BOOT) == 0 {
        return Err(Error::PermissionDenied);
    }
    if kernel_fd < 0 && flags & KEXEC_FILE_UNLOAD == 0 {
        return Err(Error::InvalidArgument);
    }
    let known = KEXEC_FILE_UNLOAD | KEXEC_FILE_ON_CRASH | KEXEC_FILE_NO_INITRAMFS;
    if flags & !known != 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (initrd_fd, cmdline_len, cmdline);
    Err(Error::NotImplemented)
}

/// Entry point for `kexec_load` from the syscall dispatcher.
pub fn do_kexec_load_syscall(
    entry: u64,
    nr_segments: u64,
    segments: u64,
    flags: u64,
    caps: u64,
) -> Result<i64> {
    sys_kexec_load(entry, nr_segments, segments, flags, caps)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_cap_rejected() {
        assert_eq!(
            sys_kexec_load(0, 0, 0, 0, 0).unwrap_err(),
            Error::PermissionDenied
        );
    }

    #[test]
    fn too_many_segments_rejected() {
        let caps = 1u64 << CAP_SYS_BOOT;
        assert_eq!(
            sys_kexec_load(0, KEXEC_SEGMENT_MAX as u64 + 1, 1, 0, caps).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn segments_needed_but_null_rejected() {
        let caps = 1u64 << CAP_SYS_BOOT;
        assert_eq!(
            sys_kexec_load(0, 1, 0, 0, caps).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn unknown_flags_rejected() {
        let caps = 1u64 << CAP_SYS_BOOT;
        assert_eq!(
            sys_kexec_load(0, 0, 0, 0x100, caps).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn zero_segments_ok_flags() {
        let caps = 1u64 << CAP_SYS_BOOT;
        assert_eq!(
            sys_kexec_load(0, 0, 0, 0, caps).unwrap_err(),
            Error::NotImplemented
        );
    }

    #[test]
    fn kexec_segment_validity() {
        let seg = KexecSegment::new(0x1000, 4096, 0x10000, 8192);
        assert!(seg.is_valid());
    }

    #[test]
    fn kexec_segment_invalid_when_memsz_less_than_bufsz() {
        let seg = KexecSegment::new(0x1000, 8192, 0x10000, 4096);
        assert!(!seg.is_valid());
    }
}
