// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `add_key(2)` syscall dispatch layer.
//!
//! Creates or updates a key in the kernel's key management facility.
//!
//! # Syscall signature
//!
//! ```text
//! key_serial_t add_key(const char *type, const char *description,
//!                      const void *payload, size_t plen,
//!                      key_serial_t keyring);
//! ```
//!
//! # Key types
//!
//! Common key types: `"user"`, `"logon"`, `"keyring"`, `"trusted"`, `"encrypted"`.
//!
//! # References
//!
//! - Linux: `security/keys/key.c` (`add_key`)
//! - `add_key(2)` man page
//! - Keyrings API: `keyrings(7)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum key type string length (including NUL).
pub const KEY_TYPE_MAX_LEN: usize = 32;

/// Maximum key description string length (including NUL).
pub const KEY_DESC_MAX_LEN: usize = 4096;

/// Maximum payload size for `add_key`.
pub const KEY_PAYLOAD_MAX: usize = 1024 * 1024; // 1 MiB

/// Special keyring serial: process's session keyring.
pub const KEY_SPEC_SESSION_KEYRING: i32 = -3;
/// Special keyring serial: process's user keyring.
pub const KEY_SPEC_USER_KEYRING: i32 = -4;
/// Special keyring serial: process's user-session keyring.
pub const KEY_SPEC_USER_SESSION_KEYRING: i32 = -5;
/// Special keyring serial: process keyring.
pub const KEY_SPEC_PROCESS_KEYRING: i32 = -2;
/// Special keyring serial: thread keyring.
pub const KEY_SPEC_THREAD_KEYRING: i32 = -1;

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Returns `true` if `keyring` is a valid special keyring or a positive key ID.
pub fn is_valid_keyring(keyring: i32) -> bool {
    keyring > 0
        || matches!(
            keyring,
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

/// Handle `add_key(2)`.
///
/// `type_ptr` and `desc_ptr` are user-space pointers to NUL-terminated strings.
/// `payload_ptr` is a user-space pointer to the key payload data; it may be
/// null only when `plen == 0`.
///
/// Returns the serial number of the new or updated key on success.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null type or description pointer, `plen`
///   exceeds limit, invalid `keyring`, or null payload when `plen > 0`.
/// - [`Error::PermissionDenied`] — insufficient privilege.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_add_key(
    type_ptr: u64,
    desc_ptr: u64,
    payload_ptr: u64,
    plen: usize,
    keyring: i32,
) -> Result<i64> {
    if type_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if desc_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if plen > KEY_PAYLOAD_MAX {
        return Err(Error::InvalidArgument);
    }
    if plen > 0 && payload_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if !is_valid_keyring(keyring) {
        return Err(Error::InvalidArgument);
    }
    let _ = (type_ptr, desc_ptr, payload_ptr, plen, keyring);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_add_key_call(
    type_ptr: u64,
    desc_ptr: u64,
    payload_ptr: u64,
    plen: usize,
    keyring: i32,
) -> Result<i64> {
    sys_add_key(type_ptr, desc_ptr, payload_ptr, plen, keyring)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_type_ptr_rejected() {
        assert_eq!(
            sys_add_key(0, 0x1000, 0, 0, KEY_SPEC_SESSION_KEYRING).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_desc_ptr_rejected() {
        assert_eq!(
            sys_add_key(0x1000, 0, 0, 0, KEY_SPEC_SESSION_KEYRING).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn oversized_payload_rejected() {
        assert_eq!(
            sys_add_key(
                0x1000,
                0x2000,
                0x3000,
                KEY_PAYLOAD_MAX + 1,
                KEY_SPEC_USER_KEYRING
            )
            .unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn nonzero_plen_null_payload_rejected() {
        assert_eq!(
            sys_add_key(0x1000, 0x2000, 0, 64, KEY_SPEC_PROCESS_KEYRING).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn invalid_keyring_rejected() {
        assert_eq!(
            sys_add_key(0x1000, 0x2000, 0, 0, -99).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn valid_call_reaches_stub() {
        let r = sys_add_key(0x1000, 0x2000, 0x3000, 16, KEY_SPEC_SESSION_KEYRING);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
