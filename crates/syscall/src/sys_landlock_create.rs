// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `landlock_create_ruleset(2)` syscall handler.
//!
//! This module provides the entry point and validation layer for the
//! `landlock_create_ruleset(2)` syscall.  The heavy state machinery lives in
//! [`crate::landlock_calls`]; this module focuses on:
//!
//! - ABI version query (`LANDLOCK_CREATE_RULESET_VERSION`)
//! - Attribute structure size validation (extensibility)
//! - Access-right bitmask validation (`LANDLOCK_ACCESS_FS_*`,
//!   `LANDLOCK_ACCESS_NET_*`)
//! - Allocation of a new ruleset file descriptor
//!
//! # Workflow
//!
//! ```text
//! user space                           kernel space
//! ──────────                           ─────────────
//! fd = landlock_create_ruleset(        validate flags
//!        &attr, size, flags)           if VERSION flag → return ABI version
//!                                      validate attr.handled_access_fs
//!                                      validate attr.handled_access_net
//!                                      allocate ruleset slot
//!                                  ◄── fd / ABI version / -errno
//! ```
//!
//! # Landlock ABI versions
//!
//! | ABI | Added access rights                                |
//! |-----|----------------------------------------------------|
//! | v1  | All `LANDLOCK_ACCESS_FS_*` except REFER, TRUNCATE  |
//! | v2  | `LANDLOCK_ACCESS_FS_REFER`                         |
//! | v3  | `LANDLOCK_ACCESS_FS_TRUNCATE`                      |
//! | v4  | `LANDLOCK_ACCESS_NET_*`                            |
//!
//! # References
//!
//! - Linux: `security/landlock/syscalls.c`
//! - man: `landlock_create_ruleset(2)`

use oncrix_lib::{Error, Result};

// Re-export public items from the main landlock module.
pub use crate::landlock_calls::{
    LANDLOCK_ABI_VERSION, LANDLOCK_ACCESS_FS_ALL, LANDLOCK_ACCESS_FS_EXECUTE,
    LANDLOCK_ACCESS_FS_MAKE_BLOCK, LANDLOCK_ACCESS_FS_MAKE_CHAR, LANDLOCK_ACCESS_FS_MAKE_DIR,
    LANDLOCK_ACCESS_FS_MAKE_FIFO, LANDLOCK_ACCESS_FS_MAKE_REG, LANDLOCK_ACCESS_FS_MAKE_SOCK,
    LANDLOCK_ACCESS_FS_MAKE_SYM, LANDLOCK_ACCESS_FS_READ_DIR, LANDLOCK_ACCESS_FS_READ_FILE,
    LANDLOCK_ACCESS_FS_REFER, LANDLOCK_ACCESS_FS_REMOVE_DIR, LANDLOCK_ACCESS_FS_REMOVE_FILE,
    LANDLOCK_ACCESS_FS_TRUNCATE, LANDLOCK_ACCESS_FS_WRITE_FILE, LANDLOCK_ACCESS_NET_ALL,
    LANDLOCK_ACCESS_NET_BIND_TCP, LANDLOCK_ACCESS_NET_CONNECT_TCP, LANDLOCK_CREATE_RULESET_VERSION,
    LandlockRulesetAttr,
};

// ---------------------------------------------------------------------------
// ABI-version-gated access masks
// ---------------------------------------------------------------------------

/// Access rights introduced in ABI v1 (all except REFER and TRUNCATE).
pub const LANDLOCK_ACCESS_FS_V1: u64 = LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_READ_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM;

/// Access right added in ABI v2.
pub const LANDLOCK_ACCESS_FS_V2: u64 = LANDLOCK_ACCESS_FS_V1 | LANDLOCK_ACCESS_FS_REFER;

/// Access right added in ABI v3.
pub const LANDLOCK_ACCESS_FS_V3: u64 = LANDLOCK_ACCESS_FS_V2 | LANDLOCK_ACCESS_FS_TRUNCATE;

/// Network access rights added in ABI v4 (full set).
pub const LANDLOCK_ACCESS_NET_V4: u64 = LANDLOCK_ACCESS_NET_ALL;

// ---------------------------------------------------------------------------
// Attribute size constants
// ---------------------------------------------------------------------------

/// Minimum valid attribute size (v1: only `handled_access_fs`).
pub const RULESET_ATTR_SIZE_V1: usize = 8; // sizeof(u64)

/// Full attribute size (v4: `handled_access_fs` + `handled_access_net`).
pub const RULESET_ATTR_SIZE_V4: usize = core::mem::size_of::<LandlockRulesetAttr>();

// ---------------------------------------------------------------------------
// Create-ruleset flags
// ---------------------------------------------------------------------------

/// Mask of all valid `landlock_create_ruleset` flags.
const CREATE_FLAGS_VALID: u32 = LANDLOCK_CREATE_RULESET_VERSION;

// ---------------------------------------------------------------------------
// Ruleset handle (wraps the fd from the lower-level module)
// ---------------------------------------------------------------------------

/// A handle to a newly-created Landlock ruleset.
///
/// Wraps the fd integer returned by the ruleset allocator so callers can
/// distinguish it from plain error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RulesetHandle(pub i32);

impl RulesetHandle {
    /// Return the underlying file descriptor number.
    pub const fn fd(self) -> i32 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate that `handled_access_fs` contains only bits supported up to
/// the current ABI version.
///
/// Returns `Err(InvalidArgument)` for any unknown bits.
fn validate_fs_access_abi(access: u64) -> Result<()> {
    // Allow all bits up to the current ABI (v3 FS + v4 net handled separately).
    if access & !LANDLOCK_ACCESS_FS_ALL != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate that `handled_access_net` contains only known network bits.
fn validate_net_access_abi(access: u64) -> Result<()> {
    if access & !LANDLOCK_ACCESS_NET_ALL != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate the attribute structure size for forward/backward compatibility.
///
/// The kernel accepts any size between `RULESET_ATTR_SIZE_V1` and
/// `sizeof(LandlockRulesetAttr)`.  Sizes beyond the known maximum are
/// rejected to catch ABI mismatches.
fn validate_attr_size(size: usize) -> Result<()> {
    if size < RULESET_ATTR_SIZE_V1 {
        return Err(Error::InvalidArgument);
    }
    if size > RULESET_ATTR_SIZE_V4 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// sys_landlock_create_ruleset
// ---------------------------------------------------------------------------

/// Handler for `landlock_create_ruleset(2)`.
///
/// # Version query
///
/// When `LANDLOCK_CREATE_RULESET_VERSION` is set in `flags`, the call does
/// not create a ruleset.  Instead it returns the current ABI version as a
/// positive integer.  `attr` must be `None` and `size` must be 0.
///
/// # Normal creation
///
/// Creates a new Landlock ruleset handling the access types specified in
/// `attr.handled_access_fs` and `attr.handled_access_net`.  Returns a
/// [`RulesetHandle`] wrapping the new ruleset file descriptor.
///
/// # Arguments
///
/// * `attr`  — Ruleset attribute (access rights to handle).  `None` is only
///             valid for a version query.
/// * `size`  — Size of the attribute structure as reported by user space.
/// * `flags` — `LANDLOCK_CREATE_RULESET_VERSION` or 0.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — Unknown flags, size out of range, unknown
///   access bits, or zero access (must handle at least one access type).
/// - [`Error::OutOfMemory`]     — No free ruleset slots.
pub fn sys_landlock_create_ruleset(
    attr: Option<&LandlockRulesetAttr>,
    size: usize,
    flags: u32,
) -> Result<i32> {
    // Reject unknown flags.
    if flags & !CREATE_FLAGS_VALID != 0 {
        return Err(Error::InvalidArgument);
    }

    // Version query: return ABI version without creating a ruleset.
    if flags & LANDLOCK_CREATE_RULESET_VERSION != 0 {
        if attr.is_some() || size != 0 {
            return Err(Error::InvalidArgument);
        }
        return Ok(LANDLOCK_ABI_VERSION as i32);
    }

    // Normal creation path: attr and size are required.
    let attr = attr.ok_or(Error::InvalidArgument)?;
    validate_attr_size(size)?;

    // At least one access type must be handled.
    if attr.handled_access_fs == 0 && attr.handled_access_net == 0 {
        return Err(Error::InvalidArgument);
    }

    validate_fs_access_abi(attr.handled_access_fs)?;
    validate_net_access_abi(attr.handled_access_net)?;

    // Delegate to the lower-level module for slot allocation.
    crate::landlock_calls::sys_landlock_create_ruleset(Some(attr), RULESET_ATTR_SIZE_V4, 0)
}

/// Determine the highest ABI version supported on this kernel.
///
/// Returns [`LANDLOCK_ABI_VERSION`].
pub fn landlock_abi_version() -> u32 {
    LANDLOCK_ABI_VERSION
}

/// Check whether a given set of filesystem access rights is supported by
/// the specified ABI version.
///
/// # Arguments
///
/// * `access` — Bitmask to test.
/// * `abi`    — Target ABI version (1–4).
///
/// Returns `true` if all bits in `access` are supported by `abi`.
pub fn fs_access_supported_by_abi(access: u64, abi: u32) -> bool {
    let mask = match abi {
        1 => LANDLOCK_ACCESS_FS_V1,
        2 => LANDLOCK_ACCESS_FS_V2,
        3 | 4 => LANDLOCK_ACCESS_FS_V3,
        _ => 0,
    };
    access & !mask == 0
}

/// Check whether a given set of network access rights is supported by
/// the specified ABI version.
///
/// Network rights are only available from ABI v4 onwards.
pub fn net_access_supported_by_abi(access: u64, abi: u32) -> bool {
    if abi < 4 {
        return access == 0;
    }
    access & !LANDLOCK_ACCESS_NET_V4 == 0
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- version query ---

    #[test]
    fn version_query_returns_abi_version() {
        let v = sys_landlock_create_ruleset(None, 0, LANDLOCK_CREATE_RULESET_VERSION).unwrap();
        assert_eq!(v, LANDLOCK_ABI_VERSION as i32);
    }

    #[test]
    fn version_query_with_attr_rejected() {
        let attr = LandlockRulesetAttr {
            handled_access_fs: LANDLOCK_ACCESS_FS_READ_FILE,
            handled_access_net: 0,
        };
        assert_eq!(
            sys_landlock_create_ruleset(
                Some(&attr),
                RULESET_ATTR_SIZE_V4,
                LANDLOCK_CREATE_RULESET_VERSION
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn version_query_nonzero_size_rejected() {
        assert_eq!(
            sys_landlock_create_ruleset(None, 8, LANDLOCK_CREATE_RULESET_VERSION),
            Err(Error::InvalidArgument)
        );
    }

    // --- normal creation ---

    #[test]
    fn create_with_fs_access_succeeds() {
        let attr = LandlockRulesetAttr {
            handled_access_fs: LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_EXECUTE,
            handled_access_net: 0,
        };
        let fd = sys_landlock_create_ruleset(Some(&attr), RULESET_ATTR_SIZE_V4, 0).unwrap();
        assert!(fd >= 0);
    }

    #[test]
    fn create_with_net_access_succeeds() {
        let attr = LandlockRulesetAttr {
            handled_access_fs: 0,
            handled_access_net: LANDLOCK_ACCESS_NET_BIND_TCP,
        };
        let fd = sys_landlock_create_ruleset(Some(&attr), RULESET_ATTR_SIZE_V4, 0).unwrap();
        assert!(fd >= 0);
    }

    #[test]
    fn create_zero_access_rejected() {
        let attr = LandlockRulesetAttr {
            handled_access_fs: 0,
            handled_access_net: 0,
        };
        assert_eq!(
            sys_landlock_create_ruleset(Some(&attr), RULESET_ATTR_SIZE_V4, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn create_without_attr_rejected() {
        assert_eq!(
            sys_landlock_create_ruleset(None, RULESET_ATTR_SIZE_V4, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn size_too_small_rejected() {
        let attr = LandlockRulesetAttr {
            handled_access_fs: LANDLOCK_ACCESS_FS_READ_FILE,
            handled_access_net: 0,
        };
        assert_eq!(
            sys_landlock_create_ruleset(Some(&attr), 0, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn size_too_large_rejected() {
        let attr = LandlockRulesetAttr {
            handled_access_fs: LANDLOCK_ACCESS_FS_READ_FILE,
            handled_access_net: 0,
        };
        assert_eq!(
            sys_landlock_create_ruleset(Some(&attr), 9999, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unknown_fs_bits_rejected() {
        let attr = LandlockRulesetAttr {
            handled_access_fs: 0xFFFF_FFFF_0000_0000,
            handled_access_net: 0,
        };
        assert_eq!(
            sys_landlock_create_ruleset(Some(&attr), RULESET_ATTR_SIZE_V4, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unknown_net_bits_rejected() {
        let attr = LandlockRulesetAttr {
            handled_access_fs: LANDLOCK_ACCESS_FS_EXECUTE,
            handled_access_net: 0xFF00,
        };
        assert_eq!(
            sys_landlock_create_ruleset(Some(&attr), RULESET_ATTR_SIZE_V4, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unknown_flags_rejected() {
        let attr = LandlockRulesetAttr {
            handled_access_fs: LANDLOCK_ACCESS_FS_READ_FILE,
            handled_access_net: 0,
        };
        assert_eq!(
            sys_landlock_create_ruleset(Some(&attr), RULESET_ATTR_SIZE_V4, 0xFF),
            Err(Error::InvalidArgument)
        );
    }

    // --- ABI compat helpers ---

    #[test]
    fn v1_rights_supported_by_abi1() {
        assert!(fs_access_supported_by_abi(LANDLOCK_ACCESS_FS_EXECUTE, 1));
        // REFER is v2 only.
        assert!(!fs_access_supported_by_abi(LANDLOCK_ACCESS_FS_REFER, 1));
    }

    #[test]
    fn refer_supported_from_abi2() {
        assert!(fs_access_supported_by_abi(LANDLOCK_ACCESS_FS_REFER, 2));
    }

    #[test]
    fn truncate_supported_from_abi3() {
        assert!(fs_access_supported_by_abi(LANDLOCK_ACCESS_FS_TRUNCATE, 3));
        assert!(!fs_access_supported_by_abi(LANDLOCK_ACCESS_FS_TRUNCATE, 2));
    }

    #[test]
    fn net_rights_require_abi4() {
        assert!(!net_access_supported_by_abi(
            LANDLOCK_ACCESS_NET_BIND_TCP,
            3
        ));
        assert!(net_access_supported_by_abi(LANDLOCK_ACCESS_NET_BIND_TCP, 4));
    }

    #[test]
    fn zero_net_rights_always_valid() {
        assert!(net_access_supported_by_abi(0, 1));
        assert!(net_access_supported_by_abi(0, 4));
    }
}
