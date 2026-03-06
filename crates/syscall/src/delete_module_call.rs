// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `delete_module(2)` syscall handler — unload a kernel module.
//!
//! `delete_module` attempts to remove a kernel module by name.  The module
//! must not be in use by any other module or process.  Requires
//! `CAP_SYS_MODULE`.
//!
//! # Syscall signature
//!
//! ```text
//! int delete_module(const char *name, unsigned int flags);
//! ```
//!
//! # Flags
//!
//! | Flag | Value | Description |
//! |------|-------|-------------|
//! | `O_NONBLOCK` | 0x800  | Fail immediately if module is busy |
//! | `O_TRUNC`    | 0x200  | Force removal even if module refuses |
//!
//! # References
//!
//! - Linux: `kernel/module/main.c`
//! - `delete_module(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Capability required to unload modules.
pub const CAP_SYS_MODULE: u32 = 16;

/// Do not wait if the module is in use; return `EWOULDBLOCK`.
pub const O_NONBLOCK: u32 = 0x800;

/// Force removal even if the module's `exit` function returns an error.
pub const O_TRUNC: u32 = 0x200;

/// Maximum module name length (including NUL terminator).
pub const MODULE_NAME_LEN: usize = 64;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// A validated module name (NUL-terminated, bounded).
#[derive(Debug, Clone, Copy)]
pub struct ModuleName {
    bytes: [u8; MODULE_NAME_LEN],
    len: usize,
}

impl ModuleName {
    /// Create a new module name from a raw byte slice.
    pub fn from_bytes(src: &[u8]) -> Result<Self> {
        if src.is_empty() || src.len() >= MODULE_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        // Module names must be ASCII alphanumeric, `-`, or `_`.
        for &b in src {
            if !matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_') {
                return Err(Error::InvalidArgument);
            }
        }
        let mut bytes = [0u8; MODULE_NAME_LEN];
        bytes[..src.len()].copy_from_slice(src);
        Ok(Self {
            bytes,
            len: src.len(),
        })
    }

    /// Return the name as a byte slice (without NUL terminator).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl Default for ModuleName {
    fn default() -> Self {
        Self {
            bytes: [0u8; MODULE_NAME_LEN],
            len: 0,
        }
    }
}

/// Request parameters for `delete_module`.
#[derive(Debug, Clone, Copy)]
pub struct DeleteModuleRequest {
    /// User-space pointer to NUL-terminated module name string.
    pub name_ptr: u64,
    /// Operation flags.
    pub flags: u32,
}

impl DeleteModuleRequest {
    /// Create a new request.
    pub const fn new(name_ptr: u64, flags: u32) -> Self {
        Self { name_ptr, flags }
    }

    /// Validate the request.
    pub fn validate(&self) -> Result<()> {
        if self.name_ptr == 0 {
            return Err(Error::InvalidArgument);
        }
        let known = O_NONBLOCK | O_TRUNC;
        if self.flags & !known != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Return whether the non-block flag is set.
    pub fn is_nonblock(&self) -> bool {
        self.flags & O_NONBLOCK != 0
    }
}

impl Default for DeleteModuleRequest {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle the `delete_module(2)` syscall.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null name pointer or unknown flags.
/// - [`Error::PermissionDenied`] — caller lacks `CAP_SYS_MODULE`.
/// - [`Error::Busy`] — module is in use and `O_NONBLOCK` was set.
/// - [`Error::NotImplemented`] — module subsystem not yet wired.
pub fn sys_delete_module(name_ptr: u64, flags: u32, caps: u64) -> Result<i64> {
    if caps & (1u64 << CAP_SYS_MODULE) == 0 {
        return Err(Error::PermissionDenied);
    }
    let req = DeleteModuleRequest::new(name_ptr, flags);
    req.validate()?;
    do_delete_module(&req)
}

fn do_delete_module(req: &DeleteModuleRequest) -> Result<i64> {
    let _ = req;
    // TODO: Look up the module by name, check reference count, call module
    // exit function, and remove from the module list.
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_delete_module_syscall(name_ptr: u64, flags: u32, caps: u64) -> Result<i64> {
    sys_delete_module(name_ptr, flags, caps)
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
            sys_delete_module(1, 0, 0).unwrap_err(),
            Error::PermissionDenied
        );
    }

    #[test]
    fn null_name_rejected() {
        let caps = 1u64 << CAP_SYS_MODULE;
        assert_eq!(
            sys_delete_module(0, 0, caps).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn unknown_flags_rejected() {
        let caps = 1u64 << CAP_SYS_MODULE;
        assert_eq!(
            sys_delete_module(1, 0x1000, caps).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn valid_module_name() {
        let name = ModuleName::from_bytes(b"my_module");
        assert!(name.is_ok());
        assert_eq!(name.unwrap().as_bytes(), b"my_module");
    }

    #[test]
    fn invalid_module_name_with_dot() {
        assert!(ModuleName::from_bytes(b"my.module").is_err());
    }

    #[test]
    fn empty_name_rejected() {
        assert!(ModuleName::from_bytes(b"").is_err());
    }

    #[test]
    fn nonblock_flag_detected() {
        let req = DeleteModuleRequest::new(1, O_NONBLOCK);
        assert!(req.is_nonblock());
    }

    #[test]
    fn request_default() {
        let req = DeleteModuleRequest::default();
        assert_eq!(req.name_ptr, 0);
    }
}
