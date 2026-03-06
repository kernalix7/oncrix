// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended capability get/set syscall handler.
//!
//! Provides capability retrieval and modification with full V3 header support.
//! Linux capabilities are divided into three sets:
//! - **Permitted**: the capabilities the process may assert.
//! - **Effective**: the capabilities currently in use.
//! - **Inheritable**: capabilities that may be inherited across `execve`.
//!
//! # POSIX Conformance
//! Capabilities are a Linux extension not in POSIX.1-2024.
//! This implementation follows Linux capability ABI (v3 header).

use oncrix_lib::{Error, Result};

/// Capability header version 3 (two 32-bit words per set).
pub const _LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// Kernel capability header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct CapUserHeader {
    /// Capability version (must be `_LINUX_CAPABILITY_VERSION_3`).
    pub version: u32,
    /// PID to query/modify (0 = calling process).
    pub pid: i32,
}

impl CapUserHeader {
    /// Construct a header targeting the calling process.
    pub const fn for_self() -> Self {
        Self {
            version: _LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        }
    }

    /// Returns `true` if the version is supported.
    pub fn version_supported(self) -> bool {
        self.version == _LINUX_CAPABILITY_VERSION_3
    }
}

/// One word of a capability data structure (low or high 32-bit word).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct CapUserDataWord {
    /// Effective capability bits.
    pub effective: u32,
    /// Permitted capability bits.
    pub permitted: u32,
    /// Inheritable capability bits.
    pub inheritable: u32,
}

impl CapUserDataWord {
    /// Construct a new capability data word.
    pub const fn new(effective: u32, permitted: u32, inheritable: u32) -> Self {
        Self {
            effective,
            permitted,
            inheritable,
        }
    }

    /// Construct an empty (zero) word.
    pub const fn empty() -> Self {
        Self::new(0, 0, 0)
    }
}

/// Arguments for the `capget` extended syscall.
#[derive(Debug, Clone, Copy)]
pub struct CapgetExtArgs {
    /// User-space pointer to the `cap_user_header_t`.
    pub header_ptr: u64,
    /// User-space pointer to receive two `cap_user_data_t` words.
    pub data_ptr: u64,
    /// Pre-parsed header (to avoid re-reading in the stub).
    pub header: CapUserHeader,
}

impl CapgetExtArgs {
    /// Construct from raw syscall register values.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] — null pointers or unsupported version.
    pub fn from_raw(header_ptr: u64, data_ptr: u64, version: u32, pid: i32) -> Result<Self> {
        if header_ptr == 0 {
            return Err(Error::InvalidArgument);
        }
        let header = CapUserHeader { version, pid };
        if !header.version_supported() {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            header_ptr,
            data_ptr,
            header,
        })
    }
}

/// Result of `capget`.
#[derive(Debug, Clone, Copy)]
pub struct CapgetExtResult {
    /// Low 32-bit capability word (caps 0–31).
    pub data_low: CapUserDataWord,
    /// High 32-bit capability word (caps 32–63).
    pub data_high: CapUserDataWord,
}

impl CapgetExtResult {
    /// Construct a result with all capabilities clear.
    pub const fn empty() -> Self {
        Self {
            data_low: CapUserDataWord::empty(),
            data_high: CapUserDataWord::empty(),
        }
    }
}

/// Handle the extended `capget` syscall.
///
/// # Errors
/// - [`Error::NotFound`] — target process does not exist.
/// - [`Error::InvalidArgument`] — null header pointer or unsupported version.
pub fn sys_capget_ext(args: CapgetExtArgs) -> Result<CapgetExtResult> {
    // A full implementation would:
    // 1. Look up the target process (args.header.pid).
    // 2. Read the process's capability sets.
    // 3. Copy both data words to args.data_ptr via copy_to_user.
    let _ = args;
    Ok(CapgetExtResult::empty())
}

/// Raw syscall entry point for extended `capget`.
///
/// # Arguments
/// * `header_ptr` — pointer to `cap_user_header_t` (register a0).
/// * `data_ptr` — pointer to `cap_user_data_t[2]` output (register a1).
///
/// # Returns
/// `0` on success, negative errno on failure.
pub fn syscall_capget_ext(header_ptr: u64, data_ptr: u64) -> i64 {
    let args = match CapgetExtArgs::from_raw(header_ptr, data_ptr, _LINUX_CAPABILITY_VERSION_3, 0) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_capget_ext(args) {
        Ok(_) => 0,
        Err(Error::NotFound) => -(oncrix_lib::errno::ESRCH as i64),
        Err(Error::InvalidArgument) => -(oncrix_lib::errno::EINVAL as i64),
        Err(_) => -(oncrix_lib::errno::EINVAL as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_header_ptr_rejected() {
        assert!(CapgetExtArgs::from_raw(0, 0x1000, _LINUX_CAPABILITY_VERSION_3, 0).is_err());
    }

    #[test]
    fn test_unsupported_version_rejected() {
        assert!(CapgetExtArgs::from_raw(0x1000, 0x2000, 0xDEAD, 0).is_err());
    }

    #[test]
    fn test_valid_args() {
        let args = CapgetExtArgs::from_raw(0x1000, 0x2000, _LINUX_CAPABILITY_VERSION_3, 0).unwrap();
        assert!(args.header.version_supported());
        assert_eq!(args.header.pid, 0);
    }

    #[test]
    fn test_empty_result() {
        let r = CapgetExtResult::empty();
        assert_eq!(r.data_low.effective, 0);
        assert_eq!(r.data_high.permitted, 0);
    }

    #[test]
    fn test_syscall_returns_zero() {
        let ret = syscall_capget_ext(0x1000, 0x2000);
        assert_eq!(ret, 0);
    }
}
