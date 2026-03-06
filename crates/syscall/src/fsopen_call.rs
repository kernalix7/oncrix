// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `fsopen(2)` syscall handler — open a filesystem configuration context.
//!
//! `fsopen` opens a filesystem context that can be configured with `fsconfig(2)`
//! and then used to create a mount with `fsmount(2)`.  This is part of the new
//! Linux mount API introduced in Linux 5.2.
//!
//! # Linux reference
//!
//! Linux-specific: `fsopen(2)` man page.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Set `FD_CLOEXEC` on the returned context fd.
pub const FSOPEN_CLOEXEC: u32 = 0x0000_0001;

/// All valid flags.
const VALID_FLAGS: u32 = FSOPEN_CLOEXEC;

/// Maximum length of a filesystem type name.
pub const FS_TYPE_NAME_MAX: usize = 64;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The phase a filesystem context can be in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsContextPhase {
    /// Context is being configured (accepting `fsconfig` calls).
    Config,
    /// Filesystem was created — context may be reconfigured.
    Created,
    /// Context has been failed and must be closed.
    Failed,
}

impl Default for FsContextPhase {
    fn default() -> Self {
        Self::Config
    }
}

/// A validated filesystem type name (up to 64 bytes, null-terminated).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsTypeName {
    buf: [u8; FS_TYPE_NAME_MAX],
    len: usize,
}

impl FsTypeName {
    /// Construct from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if the slice is empty or longer than
    /// `FS_TYPE_NAME_MAX - 1` bytes.
    pub fn from_bytes(name: &[u8]) -> Result<Self> {
        if name.is_empty() || name.len() >= FS_TYPE_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; FS_TYPE_NAME_MAX];
        buf[..name.len()].copy_from_slice(name);
        Ok(Self {
            buf,
            len: name.len(),
        })
    }

    /// Return the name as a byte slice (without the null terminator).
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Return the length of the name in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Return `true` if the name is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for FsTypeName {
    fn default() -> Self {
        Self {
            buf: [0u8; FS_TYPE_NAME_MAX],
            len: 0,
        }
    }
}

/// Parsed `fsopen` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FsopenFlags {
    /// Whether the returned fd has `FD_CLOEXEC` set.
    pub cloexec: bool,
}

impl FsopenFlags {
    /// Create a default (no-flags) value.
    pub const fn new() -> Self {
        Self { cloexec: false }
    }

    /// Parse from a raw integer.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if unknown bits are set.
    pub fn from_raw(flags: u32) -> Result<Self> {
        if flags & !VALID_FLAGS != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            cloexec: flags & FSOPEN_CLOEXEC != 0,
        })
    }
}

/// Validated `fsopen` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsopenRequest {
    /// User-space pointer to the filesystem type name string.
    pub fs_name_ptr: usize,
    /// Parsed flags.
    pub flags: FsopenFlags,
}

impl FsopenRequest {
    /// Construct a new request.
    pub const fn new(fs_name_ptr: usize, flags: FsopenFlags) -> Self {
        Self { fs_name_ptr, flags }
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `fsopen(2)`.
///
/// Validates arguments and returns a structured request.  The kernel allocates
/// a new filesystem context for the named filesystem type and returns an fd.
///
/// # Arguments
///
/// - `fs_name` — user-space pointer to a null-terminated filesystem type name
/// - `flags`   — `FSOPEN_CLOEXEC` or zero
///
/// # Errors
///
/// | `Error`           | Condition                                       |
/// |-------------------|-------------------------------------------------|
/// | `InvalidArgument` | Null pointer, unknown flags                     |
/// | `NotFound`        | The named filesystem type is not registered     |
/// | `PermissionDenied`| Insufficient privileges                         |
pub fn do_fsopen(fs_name: usize, flags: u32) -> Result<FsopenRequest> {
    if fs_name == 0 {
        return Err(Error::InvalidArgument);
    }
    let parsed_flags = FsopenFlags::from_raw(flags)?;
    Ok(FsopenRequest::new(fs_name, parsed_flags))
}

/// Validate a filesystem type name byte slice.
///
/// # Errors
///
/// Returns `Error::InvalidArgument` if the name is empty or too long.
pub fn validate_fs_name(name: &[u8]) -> Result<()> {
    if name.is_empty() || name.len() >= FS_TYPE_NAME_MAX {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Build a `FsTypeName` from a known-good byte slice (kernel side).
pub fn make_fs_type_name(name: &[u8]) -> Result<FsTypeName> {
    FsTypeName::from_bytes(name)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_open_ok() {
        let req = do_fsopen(0xDEAD_BEEF, 0).unwrap();
        assert_eq!(req.fs_name_ptr, 0xDEAD_BEEF);
        assert!(!req.flags.cloexec);
    }

    #[test]
    fn cloexec_ok() {
        let req = do_fsopen(0x1000, FSOPEN_CLOEXEC).unwrap();
        assert!(req.flags.cloexec);
    }

    #[test]
    fn null_pointer_rejected() {
        assert_eq!(do_fsopen(0, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(do_fsopen(0x1000, 0xFF), Err(Error::InvalidArgument));
    }

    #[test]
    fn fs_name_valid() {
        let name = b"ext4";
        let n = make_fs_type_name(name).unwrap();
        assert_eq!(n.as_bytes(), name);
        assert_eq!(n.len(), 4);
    }

    #[test]
    fn fs_name_empty_rejected() {
        assert_eq!(FsTypeName::from_bytes(b""), Err(Error::InvalidArgument));
    }

    #[test]
    fn fs_name_too_long_rejected() {
        let long = [b'x'; 64];
        assert_eq!(FsTypeName::from_bytes(&long), Err(Error::InvalidArgument));
    }
}
