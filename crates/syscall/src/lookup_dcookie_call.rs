// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `lookup_dcookie(2)` syscall handler — return a directory entry's path.
//!
//! `lookup_dcookie` returns the full path corresponding to the opaque 64-bit
//! dcookie (obtained from `perf_event_open`).  Used by profilers to map
//! samples back to file-system paths.  Requires `CAP_SYS_ADMIN`.
//!
//! # Syscall signature
//!
//! ```text
//! int lookup_dcookie(u64 cookie, char *buffer, size_t len);
//! ```
//!
//! # References
//!
//! - Linux: `fs/dcookies.c`
//! - `lookup_dcookie(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Capability required to look up dcookies.
pub const CAP_SYS_ADMIN: u32 = 21;

/// Maximum path length the buffer may hold (including NUL).
pub const PATH_MAX: usize = 4096;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Parameters for a `lookup_dcookie` call.
#[derive(Debug, Clone, Copy)]
pub struct LookupDcookieRequest {
    /// Opaque 64-bit dcookie.
    pub cookie: u64,
    /// User-space pointer to path output buffer.
    pub buffer: u64,
    /// Size of the output buffer in bytes.
    pub len: usize,
}

impl LookupDcookieRequest {
    /// Create a new request.
    pub const fn new(cookie: u64, buffer: u64, len: usize) -> Self {
        Self {
            cookie,
            buffer,
            len,
        }
    }

    /// Validate the request.
    pub fn validate(&self) -> Result<()> {
        if self.buffer == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.len == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.len > PATH_MAX {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for LookupDcookieRequest {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

/// Resolved path result from a dcookie lookup.
#[derive(Debug, Clone, Copy)]
pub struct DcookieResult {
    /// Number of bytes written to the output buffer (excluding NUL).
    pub written: usize,
}

impl DcookieResult {
    /// Create a new result.
    pub const fn new(written: usize) -> Self {
        Self { written }
    }
}

impl Default for DcookieResult {
    fn default() -> Self {
        Self::new(0)
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle the `lookup_dcookie(2)` syscall.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null buffer, zero len, or len > `PATH_MAX`.
/// - [`Error::PermissionDenied`] — caller lacks `CAP_SYS_ADMIN`.
/// - [`Error::NotFound`] — no entry matches `cookie`.
/// - [`Error::NotImplemented`] — dcookie subsystem not yet wired.
pub fn sys_lookup_dcookie(cookie: u64, buffer: u64, len: usize, caps: u64) -> Result<i64> {
    if caps & (1u64 << CAP_SYS_ADMIN) == 0 {
        return Err(Error::PermissionDenied);
    }
    let req = LookupDcookieRequest::new(cookie, buffer, len);
    req.validate()?;
    do_lookup_dcookie(&req)
}

fn do_lookup_dcookie(req: &LookupDcookieRequest) -> Result<i64> {
    let _ = req;
    // TODO: Look up the dcookie in the kernel's dcookie table, obtain the
    // dentry path, and copy it to user space.
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_lookup_dcookie_syscall(cookie: u64, buffer: u64, len: usize, caps: u64) -> Result<i64> {
    sys_lookup_dcookie(cookie, buffer, len, caps)
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
            sys_lookup_dcookie(1, 1, 64, 0).unwrap_err(),
            Error::PermissionDenied
        );
    }

    #[test]
    fn null_buffer_rejected() {
        let caps = 1u64 << CAP_SYS_ADMIN;
        assert_eq!(
            sys_lookup_dcookie(1, 0, 64, caps).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn zero_len_rejected() {
        let caps = 1u64 << CAP_SYS_ADMIN;
        assert_eq!(
            sys_lookup_dcookie(1, 1, 0, caps).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn too_large_len_rejected() {
        let caps = 1u64 << CAP_SYS_ADMIN;
        assert_eq!(
            sys_lookup_dcookie(1, 1, PATH_MAX + 1, caps).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn valid_request_reaches_subsystem() {
        let caps = 1u64 << CAP_SYS_ADMIN;
        assert_eq!(
            sys_lookup_dcookie(0xdeadbeef, 0x1000, 256, caps).unwrap_err(),
            Error::NotImplemented
        );
    }

    #[test]
    fn result_default_zero() {
        let r = DcookieResult::default();
        assert_eq!(r.written, 0);
    }
}
