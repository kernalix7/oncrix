// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `uname(2)` syscall handler — extended UTS namespace operations.
//!
//! Provides the kernel's UTS (Unix Time-sharing System) name information,
//! including sysname, nodename, release, version, machine, and domainname
//! strings.  This module extends the basic `uname_call.rs` with namespace-
//! aware operations and helper logic for `sethostname` / `setdomainname`.
//!
//! # Syscall signature
//!
//! ```text
//! int uname(struct utsname *buf);
//! int sethostname(const char *name, size_t len);
//! int setdomainname(const char *name, size_t len);
//! ```
//!
//! # POSIX reference
//!
//! POSIX.1-2024 §uname — `<sys/utsname.h>`.
//!
//! # References
//!
//! - Linux: `kernel/sys.c` `sys_newuname()`, `kernel/utsname.c`
//! - `uname(2)`, `sethostname(2)`, `setdomainname(2)` man pages

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum length of each UTS field (including NUL).
pub const UTS_FIELD_LEN: usize = 65;
/// Maximum hostname length (RFC 1123).
pub const HOST_NAME_MAX: usize = 64;
/// Maximum domain name length.
pub const DOMAIN_NAME_MAX: usize = 64;

/// ONCRIX sysname.
pub const ONCRIX_SYSNAME: &[u8] = b"ONCRIX";
/// ONCRIX release version.
pub const ONCRIX_RELEASE: &[u8] = b"0.1.0";
/// ONCRIX version string.
pub const ONCRIX_VERSION: &[u8] = b"#1 SMP ONCRIX 2026";
/// Machine type for x86-64.
pub const ONCRIX_MACHINE: &[u8] = b"x86_64";

// ---------------------------------------------------------------------------
// UtsName — kernel UTS fields
// ---------------------------------------------------------------------------

/// UTS name structure.
///
/// Mirrors `struct utsname` from `<sys/utsname.h>`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UtsName {
    /// Operating system name.
    pub sysname: [u8; UTS_FIELD_LEN],
    /// Node (host) name.
    pub nodename: [u8; UTS_FIELD_LEN],
    /// OS release string.
    pub release: [u8; UTS_FIELD_LEN],
    /// OS version string.
    pub version: [u8; UTS_FIELD_LEN],
    /// Hardware type.
    pub machine: [u8; UTS_FIELD_LEN],
    /// NIS/YP domain name.
    pub domainname: [u8; UTS_FIELD_LEN],
}

impl UtsName {
    /// Create a default ONCRIX UTS name with empty nodename and domainname.
    pub fn default_oncrix() -> Self {
        let mut s = Self {
            sysname: [0; UTS_FIELD_LEN],
            nodename: [0; UTS_FIELD_LEN],
            release: [0; UTS_FIELD_LEN],
            version: [0; UTS_FIELD_LEN],
            machine: [0; UTS_FIELD_LEN],
            domainname: [0; UTS_FIELD_LEN],
        };
        copy_str(&mut s.sysname, ONCRIX_SYSNAME);
        copy_str(&mut s.release, ONCRIX_RELEASE);
        copy_str(&mut s.version, ONCRIX_VERSION);
        copy_str(&mut s.machine, ONCRIX_MACHINE);
        s
    }
}

/// Copy `src` into `dst`, NUL-terminating.  Truncates silently.
fn copy_str(dst: &mut [u8; UTS_FIELD_LEN], src: &[u8]) {
    let n = src.len().min(UTS_FIELD_LEN - 1);
    dst[..n].copy_from_slice(&src[..n]);
    dst[n] = 0;
}

// ---------------------------------------------------------------------------
// UtsNamespace — per-namespace UTS record
// ---------------------------------------------------------------------------

/// Per-namespace UTS record.
///
/// In a full implementation every UTS namespace would have an independent
/// copy of the UTS fields.  Here we store one per namespace ID.
#[derive(Clone, Copy)]
pub struct UtsNamespace {
    /// Namespace ID (0 = initial namespace).
    pub ns_id: u64,
    /// UTS name data.
    pub utsname: UtsName,
}

impl UtsNamespace {
    /// Create the initial namespace.
    pub fn initial() -> Self {
        Self {
            ns_id: 0,
            utsname: UtsName::default_oncrix(),
        }
    }
}

// ---------------------------------------------------------------------------
// UtsNamespaceTable — namespace registry
// ---------------------------------------------------------------------------

/// Maximum UTS namespaces.
const MAX_NS: usize = 32;

/// Registry of UTS namespaces.
pub struct UtsNamespaceTable {
    namespaces: [Option<UtsNamespace>; MAX_NS],
}

impl UtsNamespaceTable {
    /// Create a table with the initial namespace pre-populated.
    pub fn new() -> Self {
        let mut t = Self {
            namespaces: [const { None }; MAX_NS],
        };
        t.namespaces[0] = Some(UtsNamespace::initial());
        t
    }

    /// Look up a namespace by ID.
    pub fn get(&self, ns_id: u64) -> Option<&UtsNamespace> {
        self.namespaces
            .iter()
            .filter_map(|n| n.as_ref())
            .find(|n| n.ns_id == ns_id)
    }

    /// Look up a namespace mutably by ID.
    pub fn get_mut(&mut self, ns_id: u64) -> Option<&mut UtsNamespace> {
        self.namespaces
            .iter_mut()
            .filter_map(|n| n.as_mut())
            .find(|n| n.ns_id == ns_id)
    }
}

impl Default for UtsNamespaceTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate a hostname or domain name for `sethostname` / `setdomainname`.
fn validate_hostname(name: &[u8], max_len: usize) -> Result<()> {
    if name.is_empty() || name.len() > max_len {
        return Err(Error::InvalidArgument);
    }
    // Reject embedded NUL bytes.
    if name.contains(&0) {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// sys_uname — entry point
// ---------------------------------------------------------------------------

/// Handler for `uname(2)`.
///
/// Returns the UTS information for the namespace identified by `ns_id`.
///
/// # Errors
///
/// [`Error::NotFound`] if `ns_id` is unknown.
pub fn sys_uname(table: &UtsNamespaceTable, ns_id: u64) -> Result<UtsName> {
    table.get(ns_id).map(|ns| ns.utsname).ok_or(Error::NotFound)
}

// ---------------------------------------------------------------------------
// sys_sethostname — entry point
// ---------------------------------------------------------------------------

/// Handler for `sethostname(2)`.
///
/// Sets the nodename field in the UTS namespace `ns_id`.
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — name too long / empty / contains NUL.
/// * [`Error::NotFound`]         — namespace not found.
/// * [`Error::PermissionDenied`] — caller lacks `CAP_SYS_ADMIN`.
pub fn sys_sethostname(
    table: &mut UtsNamespaceTable,
    ns_id: u64,
    name: &[u8],
    has_sys_admin: bool,
) -> Result<()> {
    if !has_sys_admin {
        return Err(Error::PermissionDenied);
    }
    validate_hostname(name, HOST_NAME_MAX)?;
    let ns = table.get_mut(ns_id).ok_or(Error::NotFound)?;
    copy_str(&mut ns.utsname.nodename, name);
    Ok(())
}

// ---------------------------------------------------------------------------
// sys_setdomainname — entry point
// ---------------------------------------------------------------------------

/// Handler for `setdomainname(2)`.
///
/// Sets the domainname field in the UTS namespace `ns_id`.
///
/// # Errors
///
/// Same as [`sys_sethostname`].
pub fn sys_setdomainname(
    table: &mut UtsNamespaceTable,
    ns_id: u64,
    name: &[u8],
    has_sys_admin: bool,
) -> Result<()> {
    if !has_sys_admin {
        return Err(Error::PermissionDenied);
    }
    validate_hostname(name, DOMAIN_NAME_MAX)?;
    let ns = table.get_mut(ns_id).ok_or(Error::NotFound)?;
    copy_str(&mut ns.utsname.domainname, name);
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_ns_has_oncrix_sysname() {
        let t = UtsNamespaceTable::new();
        let u = sys_uname(&t, 0).unwrap();
        assert_eq!(&u.sysname[..6], ONCRIX_SYSNAME);
    }

    #[test]
    fn unknown_ns_not_found() {
        let t = UtsNamespaceTable::new();
        assert_eq!(sys_uname(&t, 999), Err(Error::NotFound));
    }

    #[test]
    fn sethostname_ok() {
        let mut t = UtsNamespaceTable::new();
        sys_sethostname(&mut t, 0, b"myhost", true).unwrap();
        let u = sys_uname(&t, 0).unwrap();
        assert_eq!(&u.nodename[..6], b"myhost");
    }

    #[test]
    fn sethostname_no_cap() {
        let mut t = UtsNamespaceTable::new();
        assert_eq!(
            sys_sethostname(&mut t, 0, b"myhost", false),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn sethostname_too_long() {
        let mut t = UtsNamespaceTable::new();
        let long = [b'a'; 65];
        assert_eq!(
            sys_sethostname(&mut t, 0, &long, true),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn setdomainname_ok() {
        let mut t = UtsNamespaceTable::new();
        sys_setdomainname(&mut t, 0, b"example.com", true).unwrap();
        let u = sys_uname(&t, 0).unwrap();
        assert_eq!(&u.domainname[..11], b"example.com");
    }

    #[test]
    fn sethostname_embedded_nul() {
        let mut t = UtsNamespaceTable::new();
        assert_eq!(
            sys_sethostname(&mut t, 0, b"my\0host", true),
            Err(Error::InvalidArgument)
        );
    }
}
