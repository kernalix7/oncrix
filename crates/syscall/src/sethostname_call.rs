// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sethostname(2)` and `gethostname(2)` syscall handlers.
//!
//! Set or retrieve the network node hostname for the calling UTS namespace.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `sethostname()` / `gethostname()`.  Key behaviours:
//! - `EPERM` if the caller lacks `CAP_SYS_ADMIN`.
//! - `EINVAL` if `len` exceeds `HOST_NAME_MAX` (255).
//! - The hostname need not be NUL-terminated in the kernel; the NUL is added
//!   by `gethostname` before copying to user space.
//! - `gethostname` truncates to `len` bytes without NUL if the name is exactly
//!   `len` bytes long (POSIX-compliant).
//!
//! # References
//!
//! - POSIX.1-2024: `sethostname()`, `gethostname()`
//! - Linux man pages: `sethostname(2)`, `gethostname(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum hostname length (POSIX `HOST_NAME_MAX`).
pub const HOST_NAME_MAX: usize = 255;

// ---------------------------------------------------------------------------
// Hostname store
// ---------------------------------------------------------------------------

/// Kernel-side UTS hostname.
#[derive(Debug, Clone, Copy)]
pub struct UtsHostname {
    data: [u8; 256],
    len: usize,
}

impl Default for UtsHostname {
    fn default() -> Self {
        Self::new()
    }
}

impl UtsHostname {
    /// Create with default hostname `oncrix`.
    pub const fn new() -> Self {
        let mut data = [0u8; 256];
        data[0] = b'o';
        data[1] = b'n';
        data[2] = b'c';
        data[3] = b'r';
        data[4] = b'i';
        data[5] = b'x';
        Self { data, len: 6 }
    }

    /// Return the current hostname as a byte slice (no NUL).
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Set a new hostname.
    ///
    /// Returns `Err(InvalidArgument)` if `name` exceeds `HOST_NAME_MAX`.
    pub fn set(&mut self, name: &[u8]) -> Result<()> {
        if name.len() > HOST_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        self.data[..name.len()].copy_from_slice(name);
        // Zero out remaining bytes.
        for b in &mut self.data[name.len()..] {
            *b = 0;
        }
        self.len = name.len();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `sethostname(2)`.
///
/// # Errors
///
/// | `Error`           | Condition                              |
/// |-------------------|----------------------------------------|
/// | `PermissionDenied`| Caller lacks `CAP_SYS_ADMIN`           |
/// | `InvalidArgument` | `name` longer than `HOST_NAME_MAX`     |
pub fn do_sethostname(hostname: &mut UtsHostname, name: &[u8], cap_sys_admin: bool) -> Result<()> {
    if !cap_sys_admin {
        return Err(Error::PermissionDenied);
    }
    hostname.set(name)
}

/// Handler for `gethostname(2)`.
///
/// Copies the hostname into `buf` (up to `buf.len()` bytes), NUL-terminating
/// if there is room.  Returns the number of bytes written (including NUL).
///
/// # Errors
///
/// | `Error`           | Condition                        |
/// |-------------------|------------------------------------|
/// | `InvalidArgument` | `buf` has zero length             |
pub fn do_gethostname(hostname: &UtsHostname, buf: &mut [u8]) -> Result<usize> {
    if buf.is_empty() {
        return Err(Error::InvalidArgument);
    }
    let name = hostname.as_bytes();
    let copy_len = name.len().min(buf.len() - 1);
    buf[..copy_len].copy_from_slice(&name[..copy_len]);
    buf[copy_len] = 0;
    Ok(copy_len + 1)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sethostname_ok() {
        let mut h = UtsHostname::new();
        do_sethostname(&mut h, b"myhost", true).unwrap();
        assert_eq!(h.as_bytes(), b"myhost");
    }

    #[test]
    fn sethostname_no_cap() {
        let mut h = UtsHostname::new();
        assert_eq!(
            do_sethostname(&mut h, b"myhost", false),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn sethostname_too_long() {
        let mut h = UtsHostname::new();
        let long = [b'a'; 256];
        assert_eq!(
            do_sethostname(&mut h, &long, true),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn gethostname_ok() {
        let h = UtsHostname::new();
        let mut buf = [0u8; 64];
        let n = do_gethostname(&h, &mut buf).unwrap();
        assert_eq!(&buf[..n - 1], b"oncrix");
        assert_eq!(buf[n - 1], 0);
    }

    #[test]
    fn gethostname_truncates() {
        let h = UtsHostname::new(); // "oncrix" = 6 chars
        let mut buf = [0u8; 4]; // 3 bytes of name + NUL
        let n = do_gethostname(&h, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf[3], 0);
    }

    #[test]
    fn gethostname_empty_buf() {
        let h = UtsHostname::new();
        let mut buf: [u8; 0] = [];
        assert_eq!(do_gethostname(&h, &mut buf), Err(Error::InvalidArgument));
    }
}
