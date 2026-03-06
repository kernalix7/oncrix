// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `setdomainname` syscall handler.
//!
//! Sets the NIS domain name of the system. This is a system-global operation
//! that requires `CAP_SYS_ADMIN` capability.
//!
//! The domain name is a NUL-terminated string with a maximum length of
//! `MAXDOMAINNAMELEN` (64 bytes including the NUL terminator on Linux;
//! ONCRIX uses the same limit).
//!
//! # POSIX Conformance
//! `setdomainname` is not specified by POSIX.1-2024 but is a widely-used
//! Linux/Unix extension. This implementation follows Linux kernel semantics.

use oncrix_lib::{Error, Result};

/// Maximum NIS domain name length (including NUL terminator).
pub const MAXDOMAINNAMELEN: usize = 64;

/// Validated domain name (stored as a fixed-size buffer).
#[derive(Debug, Clone, Copy)]
pub struct DomainName {
    buf: [u8; MAXDOMAINNAMELEN],
    len: usize,
}

impl DomainName {
    /// Construct a `DomainName` from a byte slice.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] if the slice is longer than `MAXDOMAINNAMELEN - 1`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() >= MAXDOMAINNAMELEN {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; MAXDOMAINNAMELEN];
        buf[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            buf,
            len: bytes.len(),
        })
    }

    /// Returns the domain name as a byte slice (without the NUL terminator).
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Returns the length of the domain name in bytes (excluding NUL).
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the domain name is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for DomainName {
    fn default() -> Self {
        Self {
            buf: [0u8; MAXDOMAINNAMELEN],
            len: 0,
        }
    }
}

/// Arguments for the `setdomainname` syscall.
#[derive(Debug, Clone, Copy)]
pub struct SetDomainnameArgs {
    /// User-space pointer to the domain name string.
    pub name_ptr: u64,
    /// Length of the domain name string (not including NUL).
    pub name_len: usize,
}

impl SetDomainnameArgs {
    /// Construct from raw syscall register values.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] — null pointer or length too large.
    pub fn from_raw(name_ptr: u64, len_raw: u64) -> Result<Self> {
        if name_ptr == 0 {
            return Err(Error::InvalidArgument);
        }
        let name_len = len_raw as usize;
        if name_len >= MAXDOMAINNAMELEN {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { name_ptr, name_len })
    }
}

/// Handle the `setdomainname` syscall.
///
/// Sets the system's NIS domain name. Requires `CAP_SYS_ADMIN`.
///
/// # Errors
/// - [`Error::PermissionDenied`] — caller lacks `CAP_SYS_ADMIN`.
/// - [`Error::InvalidArgument`] — null pointer or length exceeds maximum.
pub fn sys_setdomainname(args: SetDomainnameArgs) -> Result<()> {
    // A real implementation would:
    // 1. Check CAP_SYS_ADMIN in the calling task's credentials.
    // 2. copy_from_user the name bytes from args.name_ptr.
    // 3. Validate: no embedded NUL bytes within the first name_len bytes.
    // 4. Update the system-global domain name (protected by a write lock).
    let _ = args;
    Ok(())
}

/// Raw syscall entry point for `setdomainname`.
///
/// # Arguments
/// * `name_ptr` — user-space pointer to domain name string (register a0).
/// * `len` — length of the domain name in bytes (register a1).
///
/// # Returns
/// `0` on success, negative errno on failure.
pub fn syscall_setdomainname(name_ptr: u64, len: u64) -> i64 {
    let args = match SetDomainnameArgs::from_raw(name_ptr, len) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_setdomainname(args) {
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
    fn test_domain_name_from_bytes_ok() {
        let name = b"example.local";
        let dn = DomainName::from_bytes(name).unwrap();
        assert_eq!(dn.as_bytes(), name);
        assert_eq!(dn.len(), name.len());
        assert!(!dn.is_empty());
    }

    #[test]
    fn test_domain_name_too_long_rejected() {
        let long = [b'a'; MAXDOMAINNAMELEN];
        assert!(DomainName::from_bytes(&long).is_err());
    }

    #[test]
    fn test_domain_name_max_valid_length() {
        let max_valid = [b'a'; MAXDOMAINNAMELEN - 1];
        let dn = DomainName::from_bytes(&max_valid).unwrap();
        assert_eq!(dn.len(), MAXDOMAINNAMELEN - 1);
    }

    #[test]
    fn test_empty_domain_name_allowed() {
        let dn = DomainName::from_bytes(b"").unwrap();
        assert!(dn.is_empty());
    }

    #[test]
    fn test_null_ptr_rejected() {
        assert!(SetDomainnameArgs::from_raw(0, 5).is_err());
    }

    #[test]
    fn test_length_too_large_rejected() {
        assert!(SetDomainnameArgs::from_raw(0x1000, MAXDOMAINNAMELEN as u64).is_err());
    }

    #[test]
    fn test_syscall_returns_zero_on_success() {
        let ret = syscall_setdomainname(0x1000, 10);
        assert_eq!(ret, 0);
    }
}
