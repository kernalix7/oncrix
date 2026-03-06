// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `uname(2)` syscall handler.
//!
//! Returns system identification information in a `Utsname` structure.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `uname()` specification.  Key behaviours:
//! - `sysname` — the operating system name.
//! - `nodename` — the network node hostname (configurable via `sethostname`).
//! - `release`  — operating system release string.
//! - `version`  — operating system version string.
//! - `machine`  — hardware identifier (e.g., `x86_64`).
//! - `domainname` — NIS/YP domain name (Linux extension).
//! - All fields are NUL-terminated and NUL-padded to 65 bytes.
//!
//! # References
//!
//! - POSIX.1-2024: `uname()`
//! - Linux man pages: `uname(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Architecture string
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
const MACHINE: &[u8] = b"x86_64";
#[cfg(target_arch = "aarch64")]
const MACHINE: &[u8] = b"aarch64";
#[cfg(target_arch = "riscv64")]
const MACHINE: &[u8] = b"riscv64";
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
)))]
const MACHINE: &[u8] = b"unknown";

// ---------------------------------------------------------------------------
// Utsname
// ---------------------------------------------------------------------------

/// POSIX `struct utsname` — system identification strings.
///
/// Each field is 65 bytes, NUL-terminated and NUL-padded.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Utsname {
    /// Operating system name.
    pub sysname: [u8; 65],
    /// Network node hostname.
    pub nodename: [u8; 65],
    /// OS release level.
    pub release: [u8; 65],
    /// OS version / build info.
    pub version: [u8; 65],
    /// Hardware identifier.
    pub machine: [u8; 65],
    /// NIS/YP domain name (Linux extension).
    pub domainname: [u8; 65],
}

impl Default for Utsname {
    fn default() -> Self {
        Self {
            sysname: [0u8; 65],
            nodename: [0u8; 65],
            release: [0u8; 65],
            version: [0u8; 65],
            machine: [0u8; 65],
            domainname: [0u8; 65],
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Copy `src` into `field`, NUL-terminating and zero-padding.
fn write_field(field: &mut [u8; 65], src: &[u8]) {
    let copy_len = src.len().min(64);
    field[..copy_len].copy_from_slice(&src[..copy_len]);
    // Ensure NUL terminator.
    field[copy_len] = 0;
    // Pad remaining bytes with zeros.
    for b in &mut field[copy_len + 1..] {
        *b = 0;
    }
}

// ---------------------------------------------------------------------------
// Global hostname storage (simplified kernel-side)
// ---------------------------------------------------------------------------

/// Maximum hostname length (POSIX HOST_NAME_MAX = 255; we cap at 64 for utsname).
pub const MAX_HOSTNAME_LEN: usize = 64;

/// Kernel hostname buffer.
pub struct HostnameStore {
    data: [u8; 65],
    len: usize,
}

impl Default for HostnameStore {
    fn default() -> Self {
        Self::new()
    }
}

impl HostnameStore {
    /// Create with default hostname `oncrix`.
    pub const fn new() -> Self {
        let mut data = [0u8; 65];
        // b"oncrix" = [111, 110, 99, 114, 105, 120]
        data[0] = b'o';
        data[1] = b'n';
        data[2] = b'c';
        data[3] = b'r';
        data[4] = b'i';
        data[5] = b'x';
        Self { data, len: 6 }
    }

    /// Return the stored hostname slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Set a new hostname.
    ///
    /// Returns `Err(InvalidArg)` if `name` exceeds `MAX_HOSTNAME_LEN`.
    pub fn set(&mut self, name: &[u8]) -> Result<()> {
        if name.len() > MAX_HOSTNAME_LEN {
            return Err(Error::InvalidArgument);
        }
        self.data[..name.len()].copy_from_slice(name);
        self.data[name.len()] = 0;
        self.len = name.len();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `uname(2)`.
///
/// Fills `buf` with ONCRIX system identification strings.
///
/// # Arguments
///
/// * `buf`      — Output `Utsname` to fill.
/// * `hostname` — Current system hostname (from kernel parameter or `sethostname`).
/// * `domainname` — Current NIS domain name.
pub fn do_uname(buf: &mut Utsname, hostname: &[u8], domainname: &[u8]) -> Result<()> {
    write_field(&mut buf.sysname, b"ONCRIX");
    write_field(&mut buf.nodename, hostname);
    write_field(&mut buf.release, b"0.1.0-oncrix");
    write_field(&mut buf.version, b"#1 SMP PREEMPT ONCRIX 0.1.0");
    write_field(&mut buf.machine, MACHINE);
    write_field(&mut buf.domainname, domainname);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uname_sysname_is_oncrix() {
        let mut buf = Utsname::default();
        do_uname(&mut buf, b"testhost", b"(none)").unwrap();
        assert_eq!(&buf.sysname[..6], b"ONCRIX");
        assert_eq!(buf.sysname[6], 0);
    }

    #[test]
    fn uname_nodename() {
        let mut buf = Utsname::default();
        do_uname(&mut buf, b"myhost", b"").unwrap();
        assert_eq!(&buf.nodename[..6], b"myhost");
        assert_eq!(buf.nodename[6], 0);
    }

    #[test]
    fn uname_machine_set() {
        let mut buf = Utsname::default();
        do_uname(&mut buf, b"host", b"").unwrap();
        // machine should be non-empty and NUL-terminated
        assert_ne!(buf.machine[0], 0);
    }

    #[test]
    fn hostname_store_set_and_get() {
        let mut store = HostnameStore::new();
        assert_eq!(store.as_bytes(), b"oncrix");
        store.set(b"myhostname").unwrap();
        assert_eq!(store.as_bytes(), b"myhostname");
    }

    #[test]
    fn hostname_too_long() {
        let mut store = HostnameStore::new();
        let long = [b'a'; 65];
        assert_eq!(store.set(&long), Err(Error::InvalidArgument));
    }
}
