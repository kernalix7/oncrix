// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `landlock_create_ruleset(2)`, `landlock_add_rule(2)`,
//! `landlock_restrict_self(2)` syscall dispatch layer.
//!
//! Landlock is a Linux security module that allows unprivileged processes to
//! sandbox themselves by creating rule sets that restrict filesystem access.
//!
//! # Syscall signatures
//!
//! ```text
//! int landlock_create_ruleset(const struct landlock_ruleset_attr *attr,
//!                             size_t size, uint32_t flags);
//! int landlock_add_rule(int ruleset_fd, enum landlock_rule_type rule_type,
//!                       const void *rule_attr, uint32_t flags);
//! int landlock_restrict_self(int ruleset_fd, uint32_t flags);
//! ```
//!
//! # References
//!
//! - Linux: `security/landlock/syscalls.c`
//! - `landlock_create_ruleset(2)`, `landlock_add_rule(2)`,
//!   `landlock_restrict_self(2)` man pages

use oncrix_lib::{Error, Result};

// Re-export constants from the existing landlock_calls module.
pub use crate::landlock_calls::{
    LANDLOCK_ACCESS_FS_EXECUTE, LANDLOCK_ACCESS_FS_READ_DIR, LANDLOCK_ACCESS_FS_READ_FILE,
    LANDLOCK_ACCESS_FS_REMOVE_DIR, LANDLOCK_ACCESS_FS_REMOVE_FILE, LANDLOCK_ACCESS_FS_WRITE_FILE,
    LANDLOCK_CREATE_RULESET_VERSION, LANDLOCK_RULE_PATH_BENEATH,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum size of `struct landlock_ruleset_attr` (ABI v1).
pub const LANDLOCK_RULESET_ATTR_SIZE_VER1: usize = 8;

/// Maximum valid file descriptor number.
const FD_MAX: i32 = 1_048_576;

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handle `landlock_create_ruleset(2)`.
///
/// When `flags` has `LANDLOCK_CREATE_RULESET_VERSION` set, `attr` and `size`
/// are ignored and the ABI version is returned.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown flags, `attr` null without the
///   version flag, or `size` too small.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_landlock_create_ruleset(attr_ptr: u64, size: usize, flags: u32) -> Result<i64> {
    let valid_flags = LANDLOCK_CREATE_RULESET_VERSION;
    if flags & !valid_flags != 0 {
        return Err(Error::InvalidArgument);
    }
    if flags & LANDLOCK_CREATE_RULESET_VERSION != 0 {
        // Return ABI version.
        return Err(Error::NotImplemented);
    }
    if attr_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if size < LANDLOCK_RULESET_ATTR_SIZE_VER1 {
        return Err(Error::InvalidArgument);
    }
    let _ = (attr_ptr, size, flags);
    Err(Error::NotImplemented)
}

/// Handle `landlock_add_rule(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — non-zero `flags`, unknown `rule_type`,
///   null `rule_attr`, or `ruleset_fd` out of range.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_landlock_add_rule(
    ruleset_fd: i32,
    rule_type: u32,
    rule_attr_ptr: u64,
    flags: u32,
) -> Result<i64> {
    if ruleset_fd < 0 || ruleset_fd > FD_MAX {
        return Err(Error::InvalidArgument);
    }
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }
    if rule_type != LANDLOCK_RULE_PATH_BENEATH {
        return Err(Error::InvalidArgument);
    }
    if rule_attr_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (ruleset_fd, rule_type, rule_attr_ptr, flags);
    Err(Error::NotImplemented)
}

/// Handle `landlock_restrict_self(2)`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — non-zero `flags` or `ruleset_fd` out of
///   range.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_landlock_restrict_self(ruleset_fd: i32, flags: u32) -> Result<i64> {
    if ruleset_fd < 0 || ruleset_fd > FD_MAX {
        return Err(Error::InvalidArgument);
    }
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (ruleset_fd, flags);
    Err(Error::NotImplemented)
}

/// Entry point for `landlock_create_ruleset` from the syscall dispatcher.
pub fn do_landlock_create_ruleset_call(attr_ptr: u64, size: usize, flags: u32) -> Result<i64> {
    sys_landlock_create_ruleset(attr_ptr, size, flags)
}

/// Entry point for `landlock_add_rule` from the syscall dispatcher.
pub fn do_landlock_add_rule_call(
    ruleset_fd: i32,
    rule_type: u32,
    rule_attr_ptr: u64,
    flags: u32,
) -> Result<i64> {
    sys_landlock_add_rule(ruleset_fd, rule_type, rule_attr_ptr, flags)
}

/// Entry point for `landlock_restrict_self` from the syscall dispatcher.
pub fn do_landlock_restrict_self_call(ruleset_fd: i32, flags: u32) -> Result<i64> {
    sys_landlock_restrict_self(ruleset_fd, flags)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_ruleset_null_attr_rejected() {
        assert_eq!(
            sys_landlock_create_ruleset(0, LANDLOCK_RULESET_ATTR_SIZE_VER1, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn create_ruleset_size_too_small_rejected() {
        assert_eq!(
            sys_landlock_create_ruleset(0x1000, 4, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn create_ruleset_version_flag_ok() {
        let r = sys_landlock_create_ruleset(0, 0, LANDLOCK_CREATE_RULESET_VERSION);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn add_rule_nonzero_flags_rejected() {
        assert_eq!(
            sys_landlock_add_rule(3, LANDLOCK_RULE_PATH_BENEATH, 0x1000, 1).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn add_rule_unknown_type_rejected() {
        assert_eq!(
            sys_landlock_add_rule(3, 99, 0x1000, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn restrict_self_nonzero_flags_rejected() {
        assert_eq!(
            sys_landlock_restrict_self(3, 1).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn restrict_self_valid() {
        let r = sys_landlock_restrict_self(3, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
