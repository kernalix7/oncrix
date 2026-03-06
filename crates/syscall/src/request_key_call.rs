// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `request_key(2)` syscall dispatch layer.
//!
//! Requests a key from the kernel's key management facility.  If the key does
//! not already exist, the kernel invokes the `request-key` user-space helper
//! to instantiate it.
//!
//! # Syscall signature
//!
//! ```text
//! key_serial_t request_key(const char *type, const char *description,
//!                          const char *callout_info,
//!                          key_serial_t dest_keyring);
//! ```
//!
//! # References
//!
//! - Linux: `security/keys/request_key.c`
//! - `request_key(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants (mirrored from add_key_call)
// ---------------------------------------------------------------------------

/// Maximum key type string length (including NUL).
pub const KEY_TYPE_MAX_LEN: usize = 32;

/// Special keyring: process's session keyring.
pub const KEY_SPEC_SESSION_KEYRING: i32 = -3;
/// Special keyring: process's user keyring.
pub const KEY_SPEC_USER_KEYRING: i32 = -4;
/// Special keyring: process's user-session keyring.
pub const KEY_SPEC_USER_SESSION_KEYRING: i32 = -5;
/// Special keyring: process keyring.
pub const KEY_SPEC_PROCESS_KEYRING: i32 = -2;
/// Special keyring: thread keyring.
pub const KEY_SPEC_THREAD_KEYRING: i32 = -1;
/// No destination keyring (0 = don't link).
pub const KEY_SPEC_NONE: i32 = 0;

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Returns `true` if `dest_keyring` is a valid destination.
///
/// A destination of 0 means "do not link the key into any keyring".
pub fn is_valid_dest(dest_keyring: i32) -> bool {
    dest_keyring >= 0
        || matches!(
            dest_keyring,
            KEY_SPEC_SESSION_KEYRING
                | KEY_SPEC_USER_KEYRING
                | KEY_SPEC_USER_SESSION_KEYRING
                | KEY_SPEC_PROCESS_KEYRING
                | KEY_SPEC_THREAD_KEYRING
        )
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `request_key(2)`.
///
/// `type_ptr` and `desc_ptr` are user-space NUL-terminated strings.
/// `callout_ptr` is optional (0 = no callout); it passes additional info to
/// the user-space helper.  `dest_keyring` is where the found key should be
/// linked.
///
/// Returns the serial number of the found or instantiated key.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null `type_ptr`, null `desc_ptr`, or
///   invalid `dest_keyring`.
/// - [`Error::NotFound`] — key not found and no callout helper instantiated it.
/// - [`Error::PermissionDenied`] — access denied.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_request_key(
    type_ptr: u64,
    desc_ptr: u64,
    callout_ptr: u64,
    dest_keyring: i32,
) -> Result<i64> {
    if type_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if desc_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if !is_valid_dest(dest_keyring) {
        return Err(Error::InvalidArgument);
    }
    let _ = (type_ptr, desc_ptr, callout_ptr, dest_keyring);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_request_key_call(
    type_ptr: u64,
    desc_ptr: u64,
    callout_ptr: u64,
    dest_keyring: i32,
) -> Result<i64> {
    sys_request_key(type_ptr, desc_ptr, callout_ptr, dest_keyring)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_type_rejected() {
        assert_eq!(
            sys_request_key(0, 0x1000, 0, KEY_SPEC_SESSION_KEYRING).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_desc_rejected() {
        assert_eq!(
            sys_request_key(0x1000, 0, 0, KEY_SPEC_USER_KEYRING).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn invalid_dest_rejected() {
        assert_eq!(
            sys_request_key(0x1000, 0x2000, 0, -99).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn no_dest_keyring_valid() {
        let r = sys_request_key(0x1000, 0x2000, 0, KEY_SPEC_NONE);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn with_callout_reaches_stub() {
        let r = sys_request_key(0x1000, 0x2000, 0x3000, KEY_SPEC_SESSION_KEYRING);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
