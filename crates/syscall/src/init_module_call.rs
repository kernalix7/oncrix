// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `init_module(2)` / `finit_module(2)` syscall handlers — load a kernel module.
//!
//! `init_module` loads an ELF image from user space into the kernel.
//! `finit_module` loads from a file descriptor.  Both require `CAP_SYS_MODULE`.
//!
//! # Syscall signatures
//!
//! ```text
//! int init_module(void *module_image, unsigned long len, const char *param_values);
//! int finit_module(int fd, const char *param_values, int flags);
//! ```
//!
//! # `finit_module` flags
//!
//! | Flag | Value | Description |
//! |------|-------|-------------|
//! | `MODULE_INIT_IGNORE_MODVERSIONS` | 1 | Ignore symbol version info |
//! | `MODULE_INIT_IGNORE_VERMAGIC`   | 2 | Ignore version magic |
//! | `MODULE_INIT_COMPRESSED_FILE`   | 4 | Module image is compressed |
//!
//! # References
//!
//! - Linux: `kernel/module/main.c`
//! - `init_module(2)`, `finit_module(2)` man pages

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Capability bit for loading kernel modules.
pub const CAP_SYS_MODULE: u32 = 16;

/// Ignore module symbol version checksums.
pub const MODULE_INIT_IGNORE_MODVERSIONS: i32 = 1;
/// Ignore kernel version magic string.
pub const MODULE_INIT_IGNORE_VERMAGIC: i32 = 2;
/// The module image on the fd is compressed.
pub const MODULE_INIT_COMPRESSED_FILE: i32 = 4;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Request for `init_module`.
#[derive(Debug, Clone, Copy)]
pub struct InitModuleRequest {
    /// User-space pointer to the ELF module image.
    pub module_image: u64,
    /// Size of the ELF image in bytes.
    pub len: u64,
    /// User-space pointer to module parameter string.
    pub param_values: u64,
}

impl InitModuleRequest {
    /// Create a new request.
    pub const fn new(module_image: u64, len: u64, param_values: u64) -> Self {
        Self {
            module_image,
            len,
            param_values,
        }
    }

    /// Validate the request.
    pub fn validate(&self) -> Result<()> {
        if self.module_image == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.len == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for InitModuleRequest {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

/// Request for `finit_module`.
#[derive(Debug, Clone, Copy)]
pub struct FinitModuleRequest {
    /// Open file descriptor pointing to the module image.
    pub fd: i32,
    /// User-space pointer to module parameter string.
    pub param_values: u64,
    /// Flags controlling module loading behaviour.
    pub flags: i32,
}

impl FinitModuleRequest {
    /// Create a new request.
    pub const fn new(fd: i32, param_values: u64, flags: i32) -> Self {
        Self {
            fd,
            param_values,
            flags,
        }
    }

    /// Validate the request.
    pub fn validate(&self) -> Result<()> {
        if self.fd < 0 {
            return Err(Error::InvalidArgument);
        }
        let known_flags = MODULE_INIT_IGNORE_MODVERSIONS
            | MODULE_INIT_IGNORE_VERMAGIC
            | MODULE_INIT_COMPRESSED_FILE;
        if self.flags & !known_flags != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for FinitModuleRequest {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handle `init_module(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null image pointer or zero length.
/// - [`Error::PermissionDenied`] — caller lacks `CAP_SYS_MODULE`.
/// - [`Error::NotImplemented`] — module loader not yet wired.
pub fn sys_init_module(module_image: u64, len: u64, param_values: u64, caps: u64) -> Result<i64> {
    if caps & (1u64 << CAP_SYS_MODULE) == 0 {
        return Err(Error::PermissionDenied);
    }
    let req = InitModuleRequest::new(module_image, len, param_values);
    req.validate()?;
    do_init_module(&req)
}

fn do_init_module(req: &InitModuleRequest) -> Result<i64> {
    let _ = req;
    Err(Error::NotImplemented)
}

/// Handle `finit_module(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — negative fd or unknown flags.
/// - [`Error::PermissionDenied`] — caller lacks `CAP_SYS_MODULE`.
/// - [`Error::NotImplemented`] — module loader not yet wired.
pub fn sys_finit_module(fd: i32, param_values: u64, flags: i32, caps: u64) -> Result<i64> {
    if caps & (1u64 << CAP_SYS_MODULE) == 0 {
        return Err(Error::PermissionDenied);
    }
    let req = FinitModuleRequest::new(fd, param_values, flags);
    req.validate()?;
    do_finit_module(&req)
}

fn do_finit_module(req: &FinitModuleRequest) -> Result<i64> {
    let _ = req;
    Err(Error::NotImplemented)
}

/// Entry point for `init_module` from the syscall dispatcher.
pub fn do_init_module_syscall(
    module_image: u64,
    len: u64,
    param_values: u64,
    caps: u64,
) -> Result<i64> {
    sys_init_module(module_image, len, param_values, caps)
}

/// Entry point for `finit_module` from the syscall dispatcher.
pub fn do_finit_module_syscall(fd: i32, param_values: u64, flags: i32, caps: u64) -> Result<i64> {
    sys_finit_module(fd, param_values, flags, caps)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_module_no_cap_rejected() {
        assert_eq!(
            sys_init_module(1, 100, 0, 0).unwrap_err(),
            Error::PermissionDenied
        );
    }

    #[test]
    fn init_module_null_image_rejected() {
        let caps = 1u64 << CAP_SYS_MODULE;
        assert_eq!(
            sys_init_module(0, 100, 0, caps).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn init_module_zero_len_rejected() {
        let caps = 1u64 << CAP_SYS_MODULE;
        assert_eq!(
            sys_init_module(1, 0, 0, caps).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn finit_module_negative_fd_rejected() {
        let caps = 1u64 << CAP_SYS_MODULE;
        assert_eq!(
            sys_finit_module(-1, 0, 0, caps).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn finit_module_unknown_flags_rejected() {
        let caps = 1u64 << CAP_SYS_MODULE;
        assert_eq!(
            sys_finit_module(0, 0, 0x80, caps).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn finit_module_no_cap_rejected() {
        assert_eq!(
            sys_finit_module(0, 0, 0, 0).unwrap_err(),
            Error::PermissionDenied
        );
    }

    #[test]
    fn finit_module_request_default() {
        let req = FinitModuleRequest::default();
        assert_eq!(req.fd, 0);
        assert_eq!(req.flags, 0);
    }
}
