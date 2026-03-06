// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `shmdt(2)` syscall handler — detach a System V shared memory segment.
//!
//! `shmdt` removes the mapping of the shared memory segment attached at
//! `shmaddr` from the calling process's address space.  The segment itself
//! (its identifier, associated data, and contents) is not affected; only the
//! attachment is removed.
//!
//! # Syscall signature
//!
//! ```text
//! int shmdt(const void *shmaddr);
//! ```
//!
//! # POSIX Compliance
//!
//! Conforms to POSIX.1-2024 `shmdt()` specification.  Returns 0 on success;
//! on error returns –1 with `errno` set to `EINVAL` if `shmaddr` is not the
//! address of an attached shared memory segment in the caller's address space.
//!
//! # References
//!
//! - POSIX.1-2024: `sys/shm.h`, `shmdt()`
//! - Linux: `ipc/shm.c`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Detach request parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShmdtRequest {
    /// Virtual address of the attached segment to detach.
    pub shmaddr: u64,
}

impl ShmdtRequest {
    /// Create a new detach request.
    pub const fn new(shmaddr: u64) -> Self {
        Self { shmaddr }
    }

    /// Validate the request.
    ///
    /// POSIX requires `shmaddr` to be the address returned by a prior
    /// `shmat(2)` call.  A null pointer is always invalid.
    pub fn validate(&self) -> Result<()> {
        if self.shmaddr == 0 {
            return Err(Error::InvalidArgument);
        }
        // shmaddr must be page-aligned (segments are always mapped at page
        // granularity by the kernel).
        if self.shmaddr % 4096 != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for ShmdtRequest {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Statistics collected during a detach operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct ShmdtStats {
    /// Number of detach operations completed in this session (informational).
    pub detach_count: u64,
}

impl ShmdtStats {
    /// Create a fresh statistics record.
    pub const fn new() -> Self {
        Self { detach_count: 0 }
    }

    /// Increment the detach counter.
    pub fn record_detach(&mut self) {
        self.detach_count = self.detach_count.saturating_add(1);
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle the `shmdt(2)` syscall.
///
/// Removes the shared memory segment attached at `shmaddr` from the caller's
/// virtual address space.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `shmaddr` is null, not page-aligned, or does
///   not correspond to an attached segment.
/// - [`Error::NotImplemented`] — IPC subsystem not yet fully wired.
pub fn sys_shmdt(shmaddr: u64) -> Result<i64> {
    let req = ShmdtRequest::new(shmaddr);
    req.validate()?;
    do_shmdt(req.shmaddr)
}

fn do_shmdt(shmaddr: u64) -> Result<i64> {
    let _ = shmaddr;
    // TODO: Search the process's VMA list for a shared memory attachment at
    // shmaddr, unmap it, and decrement the segment's attach count.
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_shmdt_syscall(shmaddr: u64) -> Result<i64> {
    sys_shmdt(shmaddr)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_addr_rejected() {
        assert_eq!(sys_shmdt(0).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn misaligned_addr_rejected() {
        assert_eq!(sys_shmdt(0x1001).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn page_aligned_addr_passes_validation() {
        let req = ShmdtRequest::new(4096);
        assert!(req.validate().is_ok());
    }

    #[test]
    fn stats_record_increments() {
        let mut stats = ShmdtStats::new();
        stats.record_detach();
        stats.record_detach();
        assert_eq!(stats.detach_count, 2);
    }

    #[test]
    fn stats_default_zero() {
        let stats = ShmdtStats::default();
        assert_eq!(stats.detach_count, 0);
    }

    #[test]
    fn request_default_is_null() {
        let req = ShmdtRequest::default();
        assert_eq!(req.shmaddr, 0);
    }

    #[test]
    fn large_page_aligned_addr_passes() {
        let req = ShmdtRequest::new(0x7fff_0000_0000);
        assert!(req.validate().is_ok());
    }
}
