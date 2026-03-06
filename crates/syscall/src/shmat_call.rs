// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `shmat(2)` syscall handler — attach a System V shared memory segment.
//!
//! `shmat` maps a shared memory segment identified by `shmid` into the calling
//! process's address space.  The segment is attached at `shmaddr` if non-null
//! (subject to alignment rules) or at a kernel-chosen address if null.
//!
//! # Syscall signature
//!
//! ```text
//! void *shmat(int shmid, const void *shmaddr, int shmflg);
//! ```
//!
//! # Flags
//!
//! | Flag | Value | Description |
//! |------|-------|-------------|
//! | `SHM_RDONLY` | 0x1000 | Attach read-only |
//! | `SHM_RND`    | 0x2000 | Round `shmaddr` down to `SHMLBA` |
//! | `SHM_REMAP`  | 0x4000 | Replace existing mapping |
//! | `SHM_EXEC`   | 0x8000 | Allow execute permission |
//!
//! # POSIX Compliance
//!
//! Conforms to POSIX.1-2024 `shmat()` specification.  The returned address is
//! the actual attach address on success; on error the syscall returns `EINVAL`,
//! `EACCES`, `ENOMEM`, or `EINVAL`.
//!
//! # References
//!
//! - POSIX.1-2024: `sys/shm.h`, `shmat()`
//! - Linux: `ipc/shm.c`, `include/uapi/linux/shm.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flag constants
// ---------------------------------------------------------------------------

/// Attach the segment read-only.
pub const SHM_RDONLY: i32 = 0x1000;
/// Round `shmaddr` to the nearest `SHMLBA` multiple.
pub const SHM_RND: i32 = 0x2000;
/// Replace any existing mapping at the specified address.
pub const SHM_REMAP: i32 = 0x4000;
/// Allow execute permission on the attached segment.
pub const SHM_EXEC: i32 = 0x8000;

/// Shared memory low boundary address (architecture-dependent; 4096 for x86_64).
pub const SHMLBA: usize = 4096;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Attachment request parameters passed to the kernel.
#[derive(Debug, Clone, Copy)]
pub struct ShmatRequest {
    /// Shared memory segment identifier.
    pub shmid: i32,
    /// Requested attach address (0 = kernel chooses).
    pub shmaddr: u64,
    /// Attachment flags (`SHM_RDONLY`, `SHM_RND`, …).
    pub shmflg: i32,
}

impl ShmatRequest {
    /// Create a new attach request.
    pub const fn new(shmid: i32, shmaddr: u64, shmflg: i32) -> Self {
        Self {
            shmid,
            shmaddr,
            shmflg,
        }
    }

    /// Return whether the read-only flag is set.
    pub fn is_readonly(&self) -> bool {
        self.shmflg & SHM_RDONLY != 0
    }

    /// Return whether the round flag is set.
    pub fn is_rnd(&self) -> bool {
        self.shmflg & SHM_RND != 0
    }

    /// Return whether the remap flag is set.
    pub fn is_remap(&self) -> bool {
        self.shmflg & SHM_REMAP != 0
    }

    /// Validate the request parameters.
    pub fn validate(&self) -> Result<()> {
        if self.shmid < 0 {
            return Err(Error::InvalidArgument);
        }
        // If SHM_RND is not set, shmaddr must be page-aligned.
        if self.shmaddr != 0 && self.shmflg & SHM_RND == 0 {
            if self.shmaddr % (SHMLBA as u64) != 0 {
                return Err(Error::InvalidArgument);
            }
        }
        // Reject unknown flags.
        let known_flags = SHM_RDONLY | SHM_RND | SHM_REMAP | SHM_EXEC;
        if self.shmflg & !known_flags != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for ShmatRequest {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

/// Result of a successful `shmat` call — the attached virtual address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShmatResult {
    /// Virtual address at which the segment was attached.
    pub addr: u64,
    /// Whether the segment was mapped read-only.
    pub read_only: bool,
}

impl ShmatResult {
    /// Create a new attach result.
    pub const fn new(addr: u64, read_only: bool) -> Self {
        Self { addr, read_only }
    }
}

impl Default for ShmatResult {
    fn default() -> Self {
        Self::new(0, false)
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle the `shmat(2)` syscall.
///
/// Maps the shared memory segment `shmid` into the caller's address space.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — invalid `shmid`, misaligned `shmaddr`, or
///   unknown flags.
/// - [`Error::PermissionDenied`] — no access permission for the segment.
/// - [`Error::OutOfMemory`] — insufficient virtual address space.
/// - [`Error::NotImplemented`] — full IPC subsystem not yet wired.
pub fn sys_shmat(shmid: i32, shmaddr: u64, shmflg: i32) -> Result<u64> {
    let req = ShmatRequest::new(shmid, shmaddr, shmflg);
    req.validate()?;

    // Apply SHM_RND: round address down to SHMLBA boundary.
    let attach_addr = if req.is_rnd() && req.shmaddr != 0 {
        req.shmaddr & !(SHMLBA as u64 - 1)
    } else {
        req.shmaddr
    };

    do_shmat(req.shmid, attach_addr, req.shmflg)
}

fn do_shmat(shmid: i32, attach_addr: u64, flags: i32) -> Result<u64> {
    let _ = (shmid, attach_addr, flags);
    // TODO: Look up the shared memory segment in the IPC namespace, verify
    // permissions, allocate a VMA in the process address space, and return the
    // attach address.
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
///
/// Returns the attach address encoded as `i64`; the caller casts to `void *`.
pub fn do_shmat_syscall(shmid: i32, shmaddr: u64, shmflg: i32) -> Result<i64> {
    let addr = sys_shmat(shmid, shmaddr, shmflg)?;
    Ok(addr as i64)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_shmid_rejected() {
        assert_eq!(sys_shmat(-1, 0, 0).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn misaligned_addr_without_rnd_rejected() {
        // Address 0x1234 is not page-aligned and SHM_RND is not set.
        assert_eq!(sys_shmat(1, 0x1234, 0).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn misaligned_addr_with_rnd_accepted_validation() {
        // Validation should pass when SHM_RND is set regardless of alignment.
        let req = ShmatRequest::new(1, 0x1234, SHM_RND);
        assert!(req.validate().is_ok());
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(sys_shmat(1, 0, 0x0001).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn request_readonly_flag() {
        let req = ShmatRequest::new(1, 0, SHM_RDONLY);
        assert!(req.is_readonly());
        assert!(!req.is_rnd());
    }

    #[test]
    fn shmat_result_default() {
        let r = ShmatResult::default();
        assert_eq!(r.addr, 0);
        assert!(!r.read_only);
    }

    #[test]
    fn valid_zero_addr_passes_validation() {
        let req = ShmatRequest::new(0, 0, 0);
        assert!(req.validate().is_ok());
    }

    #[test]
    fn page_aligned_addr_passes_validation() {
        let req = ShmatRequest::new(2, 4096, 0);
        assert!(req.validate().is_ok());
    }
}
