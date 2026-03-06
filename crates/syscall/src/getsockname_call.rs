// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getsockname(2)` syscall handler.
//!
//! Returns the current address to which the socket `sockfd` is bound.  For
//! sockets bound with port 0 (wildcard port), an ephemeral port assigned by
//! the kernel is returned.  For unbound sockets the address family is
//! returned with zeroed address fields (`INADDR_ANY` / zeroed IPv6).
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `getsockname()` specification.  Key behaviours:
//! - Returns the local bound address, even if the socket is not connected.
//! - Address is truncated to the caller's buffer if needed (POSIX).
//! - Ephemeral port for sockets that bound port 0.
//! - `AF_INET` wildcard `INADDR_ANY = 0.0.0.0`.
//!
//! # References
//!
//! - POSIX.1-2024: `getsockname()`
//! - Linux man pages: `getsockname(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Address families
// ---------------------------------------------------------------------------

/// IPv4 address family.
pub const AF_INET: u16 = 2;
/// IPv6 address family.
pub const AF_INET6: u16 = 10;
/// Unix domain socket family.
pub const AF_UNIX: u16 = 1;

// ---------------------------------------------------------------------------
// Special addresses
// ---------------------------------------------------------------------------

/// IPv4 wildcard address (0.0.0.0).
pub const INADDR_ANY: u32 = 0;

// ---------------------------------------------------------------------------
// Local address representation
// ---------------------------------------------------------------------------

/// IPv4 local socket address.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LocalSockaddrIn {
    /// Address family (`AF_INET`).
    pub sin_family: u16,
    /// Bound port in network byte order (0 if ephemeral not yet assigned).
    pub sin_port: u16,
    /// Bound IPv4 address.
    pub sin_addr: u32,
    /// Padding.
    pub sin_zero: [u8; 8],
}

/// IPv6 local socket address.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalSockaddrIn6 {
    /// Address family (`AF_INET6`).
    pub sin6_family: u16,
    /// Bound port in network byte order.
    pub sin6_port: u16,
    /// Flow info.
    pub sin6_flowinfo: u32,
    /// Bound IPv6 address.
    pub sin6_addr: [u8; 16],
    /// Scope ID.
    pub sin6_scope_id: u32,
}

impl Default for LocalSockaddrIn6 {
    fn default() -> Self {
        Self {
            sin6_family: AF_INET6,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: [0u8; 16],
            sin6_scope_id: 0,
        }
    }
}

/// Unix domain local socket address.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LocalSockaddrUn {
    /// Address family (`AF_UNIX`).
    pub sun_family: u16,
    /// Bound path.
    pub sun_path: [u8; 108],
}

impl Default for LocalSockaddrUn {
    fn default() -> Self {
        Self {
            sun_family: AF_UNIX,
            sun_path: [0u8; 108],
        }
    }
}

/// Local address returned by [`do_getsockname`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAddr {
    /// IPv4 local address.
    Inet(LocalSockaddrIn),
    /// IPv6 local address.
    Inet6(LocalSockaddrIn6),
    /// Unix domain local address.
    Unix([u8; 108]),
}

impl LocalAddr {
    /// Returns the POSIX-defined byte length of this address type.
    pub const fn addr_len(&self) -> u32 {
        match self {
            Self::Inet(_) => core::mem::size_of::<LocalSockaddrIn>() as u32,
            Self::Inet6(_) => core::mem::size_of::<LocalSockaddrIn6>() as u32,
            Self::Unix(_) => core::mem::size_of::<LocalSockaddrUn>() as u32,
        }
    }
}

// ---------------------------------------------------------------------------
// Socket bind state for getsockname
// ---------------------------------------------------------------------------

/// Bind state of a socket for `getsockname`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocknameState {
    /// Socket is bound to a concrete address.
    Bound(LocalAddr),
    /// Socket has not been bound; wildcard address + port 0.
    Unbound { family: u16 },
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

/// Result of a successful `getsockname` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocknameResult {
    /// Local address (possibly truncated).
    pub addr: LocalAddr,
    /// Actual address size (caller uses this to detect truncation).
    pub actual_len: u32,
    /// Bytes actually written to the caller's buffer.
    pub returned_len: u32,
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `getsockname(2)`.
///
/// Returns the local address of `sockfd`.  If the socket is unbound, a
/// zeroed address of the socket's family is returned.
///
/// # Errors
///
/// | `Error`    | Condition                                          |
/// |------------|----------------------------------------------------|
/// | `NotFound` | Unknown address family for an unbound socket       |
pub fn do_getsockname(state: &SocknameState, buf_len: u32) -> Result<SocknameResult> {
    let addr = match state {
        SocknameState::Bound(a) => *a,
        SocknameState::Unbound { family } => match *family {
            AF_INET => LocalAddr::Inet(LocalSockaddrIn {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: INADDR_ANY,
                sin_zero: [0u8; 8],
            }),
            AF_INET6 => LocalAddr::Inet6(LocalSockaddrIn6 {
                sin6_family: AF_INET6,
                ..Default::default()
            }),
            AF_UNIX => LocalAddr::Unix([0u8; 108]),
            _ => return Err(Error::NotFound),
        },
    };

    let actual_len = addr.addr_len();
    let returned_len = actual_len.min(buf_len);
    Ok(SocknameResult {
        addr,
        actual_len,
        returned_len,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bound_inet_ok() {
        let local = LocalSockaddrIn {
            sin_family: AF_INET,
            sin_port: u16::to_be(8080),
            sin_addr: 0x7f000001,
            sin_zero: [0u8; 8],
        };
        let state = SocknameState::Bound(LocalAddr::Inet(local));
        let res = do_getsockname(&state, 1024).unwrap();
        assert_eq!(
            res.actual_len,
            core::mem::size_of::<LocalSockaddrIn>() as u32
        );
        assert_eq!(res.returned_len, res.actual_len);
    }

    #[test]
    fn unbound_returns_inaddr_any() {
        let state = SocknameState::Unbound { family: AF_INET };
        let res = do_getsockname(&state, 1024).unwrap();
        if let LocalAddr::Inet(a) = res.addr {
            assert_eq!(a.sin_addr, INADDR_ANY);
            assert_eq!(a.sin_port, 0);
        } else {
            panic!("expected Inet");
        }
    }

    #[test]
    fn truncation() {
        let state = SocknameState::Bound(LocalAddr::Inet(Default::default()));
        let res = do_getsockname(&state, 4).unwrap();
        assert_eq!(res.returned_len, 4);
        assert!(res.actual_len > 4);
    }

    #[test]
    fn unknown_family_error() {
        let state = SocknameState::Unbound { family: 99 };
        assert_eq!(do_getsockname(&state, 128), Err(Error::NotFound));
    }
}
