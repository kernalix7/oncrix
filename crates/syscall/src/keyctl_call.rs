// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `keyctl(2)` syscall handler — kernel keyring management.
//!
//! The `keyctl` syscall provides a comprehensive interface for managing
//! cryptographic keys and keyrings in the kernel.  Keys are kernel objects
//! with a type, description, and payload; they are stored in per-process,
//! per-user, per-session, or custom keyrings.
//!
//! # Syscall signature
//!
//! ```text
//! long keyctl(int cmd, unsigned long arg2, unsigned long arg3,
//!             unsigned long arg4, unsigned long arg5);
//! ```
//!
//! # Commands
//!
//! | Command                      | Value | Description                              |
//! |------------------------------|-------|------------------------------------------|
//! | `KEYCTL_GET_KEYRING_ID`      | 0     | Get the serial of a special keyring      |
//! | `KEYCTL_JOIN_SESSION_KEYRING`| 1     | Join or create a named session keyring   |
//! | `KEYCTL_UPDATE`              | 2     | Update a key's payload                   |
//! | `KEYCTL_REVOKE`              | 3     | Revoke a key (mark it invalid)           |
//! | `KEYCTL_CHOWN`               | 4     | Change key ownership                     |
//! | `KEYCTL_SETPERM`             | 5     | Set key permissions                      |
//! | `KEYCTL_DESCRIBE`            | 6     | Describe a key                           |
//! | `KEYCTL_CLEAR`               | 7     | Clear a keyring                          |
//! | `KEYCTL_LINK`                | 8     | Link a key into a keyring                |
//! | `KEYCTL_UNLINK`              | 9     | Unlink a key from a keyring              |
//! | `KEYCTL_SEARCH`              | 10    | Search a keyring tree                    |
//! | `KEYCTL_READ`                | 11    | Read a key's payload                     |
//! | `KEYCTL_INSTANTIATE`         | 12    | Instantiate a partially constructed key  |
//! | `KEYCTL_NEGATE`              | 13    | Negate a partially constructed key       |
//! | `KEYCTL_SET_REQKEY_KEYRING`  | 14    | Set the default keyring for `request_key`|
//! | `KEYCTL_SET_TIMEOUT`         | 15    | Set key expiry time                      |
//! | `KEYCTL_ASSUME_AUTHORITY`    | 16    | Assume authority over key construction   |
//! | `KEYCTL_GET_SECURITY`        | 17    | Get key security label                   |
//! | `KEYCTL_SESSION_TO_PARENT`   | 18    | Apply session keyring to parent          |
//! | `KEYCTL_REJECT`              | 19    | Reject a key construction request        |
//! | `KEYCTL_INSTANTIATE_IOV`     | 20    | Instantiate key with iov array           |
//! | `KEYCTL_INVALIDATE`          | 21    | Invalidate a key immediately             |
//! | `KEYCTL_GET_PERSISTENT`      | 22    | Get the persistent keyring for a user    |
//! | `KEYCTL_DH_COMPUTE`          | 23    | Compute a Diffie-Hellman key             |
//! | `KEYCTL_PKEY_QUERY`          | 24    | Query public-key parameters              |
//! | `KEYCTL_PKEY_ENCRYPT`        | 25    | Encrypt data with a public key           |
//! | `KEYCTL_PKEY_DECRYPT`        | 26    | Decrypt data with a public key           |
//! | `KEYCTL_PKEY_SIGN`           | 27    | Sign data with a private key             |
//! | `KEYCTL_PKEY_VERIFY`         | 28    | Verify a signature                       |
//! | `KEYCTL_RESTRICT_KEYRING`    | 29    | Restrict link operations on a keyring    |
//! | `KEYCTL_MOVE`                | 30    | Atomically move a key between keyrings   |
//! | `KEYCTL_CAPABILITIES`        | 31    | Query keyctl capabilities                |
//! | `KEYCTL_WATCH_KEY`           | 32    | Watch a key for changes                  |
//!
//! # Special keyring IDs
//!
//! | ID | Value | Description |
//! |----|-------|-------------|
//! | `KEY_SPEC_THREAD_KEYRING`  | -1 | Per-thread keyring |
//! | `KEY_SPEC_PROCESS_KEYRING` | -2 | Per-process keyring |
//! | `KEY_SPEC_SESSION_KEYRING` | -3 | Per-session keyring |
//! | `KEY_SPEC_USER_KEYRING`    | -4 | Per-user keyring |
//! | `KEY_SPEC_USER_SESSION_KEYRING` | -5 | Per-user session keyring |
//! | `KEY_SPEC_GROUP_KEYRING`   | -6 | Per-group keyring |
//! | `KEY_SPEC_REQKEY_AUTH_KEY` | -7 | Per-request-key auth key |
//!
//! # References
//!
//! - Linux: `security/keys/keyctl.c`, `include/linux/key.h`
//! - `include/uapi/linux/keyctl.h`
//! - `keyctl(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Command constants
// ---------------------------------------------------------------------------

/// Get the ID of a special keyring.
pub const KEYCTL_GET_KEYRING_ID: i32 = 0;
/// Join or create a named session keyring.
pub const KEYCTL_JOIN_SESSION_KEYRING: i32 = 1;
/// Update a key's payload.
pub const KEYCTL_UPDATE: i32 = 2;
/// Revoke a key.
pub const KEYCTL_REVOKE: i32 = 3;
/// Change ownership of a key.
pub const KEYCTL_CHOWN: i32 = 4;
/// Set key access permissions.
pub const KEYCTL_SETPERM: i32 = 5;
/// Write a description of a key to a buffer.
pub const KEYCTL_DESCRIBE: i32 = 6;
/// Clear all keys from a keyring.
pub const KEYCTL_CLEAR: i32 = 7;
/// Link a key into a keyring.
pub const KEYCTL_LINK: i32 = 8;
/// Unlink a key from a keyring.
pub const KEYCTL_UNLINK: i32 = 9;
/// Search a keyring tree.
pub const KEYCTL_SEARCH: i32 = 10;
/// Read a key's payload.
pub const KEYCTL_READ: i32 = 11;
/// Instantiate a key being constructed.
pub const KEYCTL_INSTANTIATE: i32 = 12;
/// Negate a key being constructed.
pub const KEYCTL_NEGATE: i32 = 13;
/// Set the default request-key keyring.
pub const KEYCTL_SET_REQKEY_KEYRING: i32 = 14;
/// Set the expiry time on a key.
pub const KEYCTL_SET_TIMEOUT: i32 = 15;
/// Assume authority to instantiate a key.
pub const KEYCTL_ASSUME_AUTHORITY: i32 = 16;
/// Get the security label of a key.
pub const KEYCTL_GET_SECURITY: i32 = 17;
/// Move the session keyring to the parent process.
pub const KEYCTL_SESSION_TO_PARENT: i32 = 18;
/// Reject a key construction request.
pub const KEYCTL_REJECT: i32 = 19;
/// Instantiate a key using an iov array.
pub const KEYCTL_INSTANTIATE_IOV: i32 = 20;
/// Invalidate a key immediately.
pub const KEYCTL_INVALIDATE: i32 = 21;
/// Get the persistent keyring for a UID.
pub const KEYCTL_GET_PERSISTENT: i32 = 22;
/// Compute a Diffie-Hellman shared key.
pub const KEYCTL_DH_COMPUTE: i32 = 23;
/// Query asymmetric key parameters.
pub const KEYCTL_PKEY_QUERY: i32 = 24;
/// Asymmetric-key encrypt.
pub const KEYCTL_PKEY_ENCRYPT: i32 = 25;
/// Asymmetric-key decrypt.
pub const KEYCTL_PKEY_DECRYPT: i32 = 26;
/// Asymmetric-key sign.
pub const KEYCTL_PKEY_SIGN: i32 = 27;
/// Asymmetric-key verify.
pub const KEYCTL_PKEY_VERIFY: i32 = 28;
/// Restrict key-link operations on a keyring.
pub const KEYCTL_RESTRICT_KEYRING: i32 = 29;
/// Atomically move a key between keyrings.
pub const KEYCTL_MOVE: i32 = 30;
/// Query keyctl capabilities.
pub const KEYCTL_CAPABILITIES: i32 = 31;
/// Watch a key for change notifications.
pub const KEYCTL_WATCH_KEY: i32 = 32;

// ---------------------------------------------------------------------------
// Special keyring serial numbers
// ---------------------------------------------------------------------------

/// The calling thread's own keyring.
pub const KEY_SPEC_THREAD_KEYRING: i32 = -1;
/// The calling process's own keyring.
pub const KEY_SPEC_PROCESS_KEYRING: i32 = -2;
/// The current session keyring.
pub const KEY_SPEC_SESSION_KEYRING: i32 = -3;
/// The calling user's own keyring.
pub const KEY_SPEC_USER_KEYRING: i32 = -4;
/// The calling user's session keyring.
pub const KEY_SPEC_USER_SESSION_KEYRING: i32 = -5;
/// The calling process's group keyring.
pub const KEY_SPEC_GROUP_KEYRING: i32 = -6;
/// The key being constructed's authorisation key.
pub const KEY_SPEC_REQKEY_AUTH_KEY: i32 = -7;
/// The requestor's session keyring.
pub const KEY_SPEC_REQUESTOR_KEYRING: i32 = -8;

// ---------------------------------------------------------------------------
// Permission bits
// ---------------------------------------------------------------------------

/// View key attributes.
pub const KEY_POS_VIEW: u32 = 0x0100_0000;
/// Read key payload.
pub const KEY_POS_READ: u32 = 0x0200_0000;
/// Write/update key payload.
pub const KEY_POS_WRITE: u32 = 0x0400_0000;
/// Search for keys.
pub const KEY_POS_SEARCH: u32 = 0x0800_0000;
/// Link key into keyring.
pub const KEY_POS_LINK: u32 = 0x1000_0000;
/// Set key attributes.
pub const KEY_POS_SETATTR: u32 = 0x2000_0000;

// ---------------------------------------------------------------------------
// Capability flags for KEYCTL_CAPABILITIES
// ---------------------------------------------------------------------------

/// Keyctl capabilities index 0.
pub const KEYCTL_CAPS0_CAPABILITIES: u8 = 0x01;
/// Persistent keyrings are supported.
pub const KEYCTL_CAPS0_PERSISTENT_KEYRINGS: u8 = 0x02;
/// Diffie-Hellman is supported.
pub const KEYCTL_CAPS0_DIFFIE_HELLMAN: u8 = 0x04;
/// Public key operations are supported.
pub const KEYCTL_CAPS0_PUBLIC_KEY_OPERATION: u8 = 0x08;
/// Big-key type is supported.
pub const KEYCTL_CAPS0_BIG_KEY: u8 = 0x10;
/// Restrict-keyring is supported.
pub const KEYCTL_CAPS0_RESTRICT_KEYRING: u8 = 0x20;
/// Move-key is supported.
pub const KEYCTL_CAPS0_MOVE: u8 = 0x40;
/// NS keyrings are supported.
pub const KEYCTL_CAPS0_NS_KEYRINGS: u8 = 0x80;

/// Keyctl capabilities index 1.
pub const KEYCTL_CAPS1_NS_KEY_TAG: u8 = 0x01;
/// Watch-queue notification is supported.
pub const KEYCTL_CAPS1_NOTIFICATIONS: u8 = 0x02;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle the `keyctl(2)` syscall.
///
/// `cmd` selects the operation; `arg2`–`arg5` carry operation-specific
/// arguments.  Returns a command-specific non-negative value on success.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown command or invalid argument.
/// - [`Error::NotFound`] — referenced key or keyring does not exist.
/// - [`Error::PermissionDenied`] — insufficient permissions on the key.
/// - [`Error::NotImplemented`] — command is valid but not yet implemented.
pub fn sys_keyctl(cmd: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> Result<i64> {
    match cmd {
        KEYCTL_GET_KEYRING_ID => do_get_keyring_id(arg2 as i32, arg3 as i32),
        KEYCTL_JOIN_SESSION_KEYRING => do_join_session_keyring(arg2),
        KEYCTL_UPDATE => do_update(arg2 as i32, arg3, arg4 as u32),
        KEYCTL_REVOKE => do_revoke(arg2 as i32),
        KEYCTL_CHOWN => do_chown(arg2 as i32, arg3 as u32, arg4 as u32),
        KEYCTL_SETPERM => do_setperm(arg2 as i32, arg3 as u32),
        KEYCTL_DESCRIBE => do_describe(arg2 as i32, arg3, arg4 as u32),
        KEYCTL_CLEAR => do_clear(arg2 as i32),
        KEYCTL_LINK => do_link(arg2 as i32, arg3 as i32),
        KEYCTL_UNLINK => do_unlink(arg2 as i32, arg3 as i32),
        KEYCTL_SEARCH => do_search(arg2 as i32, arg3, arg4, arg5),
        KEYCTL_READ => do_read(arg2 as i32, arg3, arg4 as u32),
        KEYCTL_INSTANTIATE => do_instantiate(arg2 as i32, arg3, arg4 as u32, arg5 as i32),
        KEYCTL_NEGATE => do_negate(arg2 as i32, arg3 as u32, arg4 as i32),
        KEYCTL_SET_REQKEY_KEYRING => do_set_reqkey_keyring(arg2 as i32),
        KEYCTL_SET_TIMEOUT => do_set_timeout(arg2 as i32, arg3 as u32),
        KEYCTL_ASSUME_AUTHORITY => do_assume_authority(arg2 as i32),
        KEYCTL_GET_SECURITY => do_get_security(arg2 as i32, arg3, arg4 as u32),
        KEYCTL_SESSION_TO_PARENT => do_session_to_parent(),
        KEYCTL_REJECT => do_reject(arg2 as i32, arg3 as u32, arg4 as u32, arg5 as i32),
        KEYCTL_INVALIDATE => do_invalidate(arg2 as i32),
        KEYCTL_GET_PERSISTENT => do_get_persistent(arg2 as u32, arg3 as i32),
        KEYCTL_CAPABILITIES => do_capabilities(arg2, arg3 as u32),
        KEYCTL_MOVE => do_move(arg2 as i32, arg3 as i32, arg4 as i32, arg5 as u32),
        KEYCTL_RESTRICT_KEYRING => do_restrict_keyring(arg2 as i32, arg3, arg4),
        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// Per-command stubs
// ---------------------------------------------------------------------------

fn do_get_keyring_id(id: i32, create: i32) -> Result<i64> {
    // Validate special keyring IDs.
    match id {
        KEY_SPEC_THREAD_KEYRING
        | KEY_SPEC_PROCESS_KEYRING
        | KEY_SPEC_SESSION_KEYRING
        | KEY_SPEC_USER_KEYRING
        | KEY_SPEC_USER_SESSION_KEYRING
        | KEY_SPEC_GROUP_KEYRING
        | KEY_SPEC_REQKEY_AUTH_KEY
        | KEY_SPEC_REQUESTOR_KEYRING => {}
        n if n > 0 => {} // Positive serial numbers are valid real keys.
        _ => return Err(Error::InvalidArgument),
    }
    let _ = create;
    // TODO: look up/allocate the keyring and return its serial.
    Err(Error::NotImplemented)
}

fn do_join_session_keyring(name_ptr: u64) -> Result<i64> {
    let _ = name_ptr;
    // TODO: join or create a named session keyring.
    Err(Error::NotImplemented)
}

fn do_update(key: i32, payload: u64, plen: u32) -> Result<i64> {
    if key <= 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (payload, plen);
    Err(Error::NotImplemented)
}

fn do_revoke(key: i32) -> Result<i64> {
    if key <= 0 {
        return Err(Error::InvalidArgument);
    }
    Err(Error::NotImplemented)
}

fn do_chown(key: i32, uid: u32, gid: u32) -> Result<i64> {
    if key <= 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (uid, gid);
    Err(Error::NotImplemented)
}

fn do_setperm(key: i32, perm: u32) -> Result<i64> {
    if key <= 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = perm;
    Err(Error::NotImplemented)
}

fn do_describe(key: i32, buf: u64, buflen: u32) -> Result<i64> {
    if key == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (buf, buflen);
    Err(Error::NotImplemented)
}

fn do_clear(keyring: i32) -> Result<i64> {
    if keyring == 0 {
        return Err(Error::InvalidArgument);
    }
    Err(Error::NotImplemented)
}

fn do_link(key: i32, keyring: i32) -> Result<i64> {
    if key == 0 || keyring == 0 {
        return Err(Error::InvalidArgument);
    }
    Err(Error::NotImplemented)
}

fn do_unlink(key: i32, keyring: i32) -> Result<i64> {
    if key == 0 || keyring == 0 {
        return Err(Error::InvalidArgument);
    }
    Err(Error::NotImplemented)
}

fn do_search(keyring: i32, type_ptr: u64, desc_ptr: u64, dest: u64) -> Result<i64> {
    if keyring == 0 || type_ptr == 0 || desc_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = dest;
    Err(Error::NotImplemented)
}

fn do_read(key: i32, buf: u64, buflen: u32) -> Result<i64> {
    if key == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (buf, buflen);
    Err(Error::NotImplemented)
}

fn do_instantiate(key: i32, payload: u64, plen: u32, keyring: i32) -> Result<i64> {
    if key <= 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (payload, plen, keyring);
    Err(Error::NotImplemented)
}

fn do_negate(key: i32, timeout: u32, keyring: i32) -> Result<i64> {
    if key <= 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (timeout, keyring);
    Err(Error::NotImplemented)
}

fn do_set_reqkey_keyring(reqkey_defl: i32) -> Result<i64> {
    let _ = reqkey_defl;
    Err(Error::NotImplemented)
}

fn do_set_timeout(key: i32, timeout: u32) -> Result<i64> {
    if key <= 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = timeout;
    Err(Error::NotImplemented)
}

fn do_assume_authority(key: i32) -> Result<i64> {
    let _ = key;
    Err(Error::NotImplemented)
}

fn do_get_security(key: i32, buf: u64, buflen: u32) -> Result<i64> {
    if key == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (buf, buflen);
    Err(Error::NotImplemented)
}

fn do_session_to_parent() -> Result<i64> {
    Err(Error::NotImplemented)
}

fn do_reject(key: i32, timeout: u32, error: u32, keyring: i32) -> Result<i64> {
    if key <= 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (timeout, error, keyring);
    Err(Error::NotImplemented)
}

fn do_invalidate(key: i32) -> Result<i64> {
    if key <= 0 {
        return Err(Error::InvalidArgument);
    }
    Err(Error::NotImplemented)
}

fn do_get_persistent(uid: u32, dest_keyring: i32) -> Result<i64> {
    let _ = (uid, dest_keyring);
    Err(Error::NotImplemented)
}

fn do_capabilities(buf: u64, buflen: u32) -> Result<i64> {
    if buf == 0 || buflen == 0 {
        return Err(Error::InvalidArgument);
    }
    let caps: [u8; 2] = [
        KEYCTL_CAPS0_CAPABILITIES
            | KEYCTL_CAPS0_PERSISTENT_KEYRINGS
            | KEYCTL_CAPS0_DIFFIE_HELLMAN
            | KEYCTL_CAPS0_PUBLIC_KEY_OPERATION
            | KEYCTL_CAPS0_RESTRICT_KEYRING
            | KEYCTL_CAPS0_MOVE,
        KEYCTL_CAPS1_NOTIFICATIONS,
    ];
    let copy_len = (buflen as usize).min(caps.len());
    // SAFETY: Caller validates user-space pointer.
    unsafe {
        core::ptr::copy_nonoverlapping(caps.as_ptr(), buf as *mut u8, copy_len);
    }
    Ok(copy_len as i64)
}

fn do_move(key: i32, from_keyring: i32, to_keyring: i32, flags: u32) -> Result<i64> {
    if key <= 0 || from_keyring == 0 || to_keyring == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = flags;
    Err(Error::NotImplemented)
}

fn do_restrict_keyring(keyring: i32, type_ptr: u64, restriction_ptr: u64) -> Result<i64> {
    if keyring == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (type_ptr, restriction_ptr);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_keyctl(cmd: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> Result<i64> {
    sys_keyctl(cmd, arg2, arg3, arg4, arg5)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_command_rejected() {
        assert_eq!(
            sys_keyctl(999, 0, 0, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn get_keyring_id_invalid_id() {
        assert_eq!(
            sys_keyctl(KEYCTL_GET_KEYRING_ID as i32, 0_u64, 0, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn capabilities_returns_length() {
        let mut buf = [0u8; 2];
        let r = sys_keyctl(KEYCTL_CAPABILITIES as i32, buf.as_mut_ptr() as u64, 2, 0, 0);
        assert_eq!(r, Ok(2));
        assert_ne!(buf[0], 0);
    }

    #[test]
    fn capabilities_null_buf_rejected() {
        assert_eq!(
            sys_keyctl(KEYCTL_CAPABILITIES as i32, 0, 0, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn revoke_negative_key_rejected() {
        assert_eq!(
            sys_keyctl(KEYCTL_REVOKE as i32, (-1_i32) as u64, 0, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }
}
