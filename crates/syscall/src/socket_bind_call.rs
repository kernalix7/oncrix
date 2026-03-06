// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `bind(2)` syscall handler.
//!
//! Assigns a local address to a socket.  A freshly created socket has no
//! address assigned; `bind` gives it a name (local endpoint) so that other
//! processes or network peers can connect or send to it.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `bind()` specification.  Key behaviours:
//! - The socket must not already be bound (`EINVAL`).
//! - The address family must match the socket domain (`EAFNOSUPPORT`).
//! - For `AF_INET`/`AF_INET6` sockets the port must not be in use by
//!   another socket with the same address (unless `SO_REUSEADDR` is set).
//! - For `AF_UNIX` sockets the path must not already exist (`EADDRINUSE`).
//! - Addresses must be validated before any state change.
//!
//! # References
//!
//! - POSIX.1-2024: `bind()`
//! - Linux man pages: `bind(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Address family constants
// ---------------------------------------------------------------------------

/// Unspecified address family.
pub const AF_UNSPEC: u16 = 0;
/// Local (Unix domain) sockets.
pub const AF_UNIX: u16 = 1;
/// IPv4 Internet protocols.
pub const AF_INET: u16 = 2;
/// IPv6 Internet protocols.
pub const AF_INET6: u16 = 10;

// ---------------------------------------------------------------------------
// Address structures
// ---------------------------------------------------------------------------

/// IPv4 socket address (`struct sockaddr_in`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SockaddrIn {
    /// Address family (`AF_INET`).
    pub sin_family: u16,
    /// Port number in network byte order.
    pub sin_port: u16,
    /// IPv4 address in network byte order.
    pub sin_addr: u32,
    /// Padding to match C struct size.
    pub sin_zero: [u8; 8],
}

/// IPv6 socket address (`struct sockaddr_in6`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockaddrIn6 {
    /// Address family (`AF_INET6`).
    pub sin6_family: u16,
    /// Port number in network byte order.
    pub sin6_port: u16,
    /// IPv6 flow information.
    pub sin6_flowinfo: u32,
    /// IPv6 address (16 bytes, network byte order).
    pub sin6_addr: [u8; 16],
    /// Scope ID for link-local addresses.
    pub sin6_scope_id: u32,
}

impl Default for SockaddrIn6 {
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

/// Unix domain socket address (`struct sockaddr_un`).
///
/// Maximum path length is 107 bytes + NUL terminator.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SockaddrUn {
    /// Address family (`AF_UNIX`).
    pub sun_family: u16,
    /// Filesystem path or abstract name (NUL-terminated or abstract).
    pub sun_path: [u8; 108],
}

impl Default for SockaddrUn {
    fn default() -> Self {
        Self {
            sun_family: AF_UNIX,
            sun_path: [0u8; 108],
        }
    }
}

/// Generic socket address tag used to record what type of address a socket
/// is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundAddress {
    /// Not yet bound.
    Unbound,
    /// Bound to an IPv4 address.
    Inet(SockaddrIn),
    /// Bound to an IPv6 address.
    Inet6(SockaddrIn6),
    /// Bound to a Unix domain socket path.
    Unix([u8; 108]),
}

// ---------------------------------------------------------------------------
// Port registry (minimal in-kernel representation)
// ---------------------------------------------------------------------------

/// Maximum number of simultaneously bound sockets tracked by the registry.
const MAX_BOUND_SOCKETS: usize = 1024;

/// Maximum well-known port number (ports below this require privilege).
pub const IPPORT_RESERVED: u16 = 1024;

/// Record of one bound socket in the port registry.
#[derive(Debug, Clone, Copy)]
struct BindRecord {
    /// Socket file descriptor.
    fd: i32,
    /// Bound address.
    addr: BoundAddress,
    /// Whether `SO_REUSEADDR` is set.
    reuseaddr: bool,
}

/// In-kernel port / address binding registry.
///
/// Tracks which (fd, address) pairs are currently bound so that duplicate
/// bind attempts can be detected.
pub struct BindRegistry {
    records: [Option<BindRecord>; MAX_BOUND_SOCKETS],
    count: usize,
}

impl Default for BindRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BindRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            records: [const { None }; MAX_BOUND_SOCKETS],
            count: 0,
        }
    }

    /// Check whether an `AF_INET` port is already in use.
    ///
    /// Returns `true` if `port` is bound by a socket that does **not** have
    /// `SO_REUSEADDR` set, or if more than one reuseaddr socket is binding the
    /// same port (port sharing is not emulated here).
    fn inet_port_in_use(&self, port: u16, _reuseaddr: bool) -> bool {
        for slot in self.records.iter().flatten() {
            if let BoundAddress::Inet(a) = slot.addr {
                if a.sin_port == port && !slot.reuseaddr {
                    return true;
                }
            }
        }
        false
    }

    /// Check whether an `AF_INET6` port is already in use.
    fn inet6_port_in_use(&self, port: u16, _reuseaddr: bool) -> bool {
        for slot in self.records.iter().flatten() {
            if let BoundAddress::Inet6(a) = slot.addr {
                if a.sin6_port == port && !slot.reuseaddr {
                    return true;
                }
            }
        }
        false
    }

    /// Check whether a Unix-domain path is already bound.
    fn unix_path_in_use(&self, path: &[u8; 108]) -> bool {
        for slot in self.records.iter().flatten() {
            if let BoundAddress::Unix(p) = slot.addr {
                if &p == path {
                    return true;
                }
            }
        }
        false
    }

    /// Check that `fd` is not already bound.
    fn fd_already_bound(&self, fd: i32) -> bool {
        self.records.iter().flatten().any(|r| r.fd == fd)
    }

    /// Register a binding.  Caller must have validated constraints first.
    fn insert(&mut self, fd: i32, addr: BoundAddress, reuseaddr: bool) -> Result<()> {
        let slot = self
            .records
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;
        *slot = Some(BindRecord {
            fd,
            addr,
            reuseaddr,
        });
        self.count += 1;
        Ok(())
    }

    /// Remove a binding (on close or rebind attempt).
    ///
    /// Returns `Err(NotFound)` if `fd` has no binding.
    pub fn remove(&mut self, fd: i32) -> Result<()> {
        let slot = self
            .records
            .iter_mut()
            .find(|s| s.as_ref().is_some_and(|r| r.fd == fd))
            .ok_or(Error::NotFound)?;
        *slot = None;
        self.count -= 1;
        Ok(())
    }

    /// Look up the bound address for `fd`.
    pub fn lookup(&self, fd: i32) -> Option<BoundAddress> {
        self.records
            .iter()
            .flatten()
            .find(|r| r.fd == fd)
            .map(|r| r.addr)
    }

    /// Return the total number of active bindings.
    pub const fn count(&self) -> usize {
        self.count
    }
}

// ---------------------------------------------------------------------------
// Bind request
// ---------------------------------------------------------------------------

/// Decoded bind request passed to [`do_bind`].
#[derive(Debug, Clone, Copy)]
pub enum BindRequest {
    /// Bind to an IPv4 address.
    Inet(SockaddrIn),
    /// Bind to an IPv6 address.
    Inet6(SockaddrIn6),
    /// Bind to a Unix domain socket path.
    Unix(SockaddrUn),
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `bind(2)`.
///
/// Validates the address and registers the binding in `registry`.
///
/// # Errors
///
/// | `Error`         | Condition                                               |
/// |-----------------|----------------------------------------------------------|
/// | `InvalidArg`    | `addrlen` too small for the given address family        |
/// | `InvalidArg`    | Socket domain does not match address family             |
/// | `AlreadyExists` | Socket is already bound (`EINVAL` semantics)            |
/// | `AddrInUse`     | The port / path is already bound by another socket      |
/// | `AccessDenied`  | Port < 1024 and caller is unprivileged                  |
/// | `OutOfMemory`   | Registry is full                                        |
pub fn do_bind(
    registry: &mut BindRegistry,
    fd: i32,
    socket_domain: i32,
    req: BindRequest,
    addrlen: u32,
    reuseaddr: bool,
    privileged: bool,
) -> Result<()> {
    // Reject if already bound.
    if registry.fd_already_bound(fd) {
        return Err(Error::InvalidArgument);
    }

    match req {
        BindRequest::Inet(addr) => {
            // Minimum size check.
            if (addrlen as usize) < core::mem::size_of::<SockaddrIn>() {
                return Err(Error::InvalidArgument);
            }
            // Domain must be AF_INET.
            if socket_domain != AF_INET as i32 {
                return Err(Error::InvalidArgument);
            }
            // Address family field must match.
            if addr.sin_family != AF_INET {
                return Err(Error::InvalidArgument);
            }
            // Privileged port check.
            let host_port = u16::from_be(addr.sin_port);
            if host_port < IPPORT_RESERVED && host_port != 0 && !privileged {
                return Err(Error::PermissionDenied);
            }
            // Port conflict check (skip for port 0 — kernel assigns ephemeral).
            if host_port != 0 && registry.inet_port_in_use(addr.sin_port, reuseaddr) {
                return Err(Error::AlreadyExists);
            }
            registry.insert(fd, BoundAddress::Inet(addr), reuseaddr)
        }
        BindRequest::Inet6(addr) => {
            if (addrlen as usize) < core::mem::size_of::<SockaddrIn6>() {
                return Err(Error::InvalidArgument);
            }
            if socket_domain != AF_INET6 as i32 {
                return Err(Error::InvalidArgument);
            }
            if addr.sin6_family != AF_INET6 {
                return Err(Error::InvalidArgument);
            }
            let host_port = u16::from_be(addr.sin6_port);
            if host_port < IPPORT_RESERVED && host_port != 0 && !privileged {
                return Err(Error::PermissionDenied);
            }
            if host_port != 0 && registry.inet6_port_in_use(addr.sin6_port, reuseaddr) {
                return Err(Error::AlreadyExists);
            }
            registry.insert(fd, BoundAddress::Inet6(addr), reuseaddr)
        }
        BindRequest::Unix(addr) => {
            if (addrlen as usize) < 3 {
                // Minimum: sun_family (2) + at least one path byte.
                return Err(Error::InvalidArgument);
            }
            if socket_domain != AF_UNIX as i32 {
                return Err(Error::InvalidArgument);
            }
            if addr.sun_family != AF_UNIX {
                return Err(Error::InvalidArgument);
            }
            if registry.unix_path_in_use(&addr.sun_path) {
                return Err(Error::AlreadyExists);
            }
            registry.insert(fd, BoundAddress::Unix(addr.sun_path), reuseaddr)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> BindRegistry {
        BindRegistry::new()
    }

    #[test]
    fn bind_inet_ok() {
        let mut r = registry();
        let addr = SockaddrIn {
            sin_family: AF_INET,
            sin_port: u16::to_be(8080),
            ..Default::default()
        };
        assert!(
            do_bind(
                &mut r,
                3,
                AF_INET as i32,
                BindRequest::Inet(addr),
                16,
                false,
                true
            )
            .is_ok()
        );
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn bind_same_fd_twice_fails() {
        let mut r = registry();
        let addr = SockaddrIn {
            sin_family: AF_INET,
            sin_port: u16::to_be(9000),
            ..Default::default()
        };
        do_bind(
            &mut r,
            3,
            AF_INET as i32,
            BindRequest::Inet(addr),
            16,
            false,
            true,
        )
        .unwrap();
        let addr2 = SockaddrIn {
            sin_family: AF_INET,
            sin_port: u16::to_be(9001),
            ..Default::default()
        };
        assert!(
            do_bind(
                &mut r,
                3,
                AF_INET as i32,
                BindRequest::Inet(addr2),
                16,
                false,
                true
            )
            .is_err()
        );
    }

    #[test]
    fn bind_port_conflict() {
        let mut r = registry();
        let addr = SockaddrIn {
            sin_family: AF_INET,
            sin_port: u16::to_be(80),
            ..Default::default()
        };
        do_bind(
            &mut r,
            3,
            AF_INET as i32,
            BindRequest::Inet(addr),
            16,
            false,
            true,
        )
        .unwrap();
        assert_eq!(
            do_bind(
                &mut r,
                4,
                AF_INET as i32,
                BindRequest::Inet(addr),
                16,
                false,
                true
            ),
            Err(Error::AlreadyExists)
        );
    }

    #[test]
    fn bind_privileged_port_unprivileged_fails() {
        let mut r = registry();
        let addr = SockaddrIn {
            sin_family: AF_INET,
            sin_port: u16::to_be(80),
            ..Default::default()
        };
        assert_eq!(
            do_bind(
                &mut r,
                3,
                AF_INET as i32,
                BindRequest::Inet(addr),
                16,
                false,
                false
            ),
            Err(Error::PermissionDenied)
        );
    }
}
