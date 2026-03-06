// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getsockopt(2)` and `setsockopt(2)` syscall handlers.
//!
//! These syscalls retrieve and set options on a socket.  Options are
//! organised by `level`: `SOL_SOCKET` for generic socket-level options,
//! `IPPROTO_TCP` for TCP-specific options, `IPPROTO_IPV6` for IPv6 options,
//! and so on.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `getsockopt()` and `setsockopt()` specifications.
//!
//! Key behaviours:
//! - `optval` is a pointer to a buffer; `optlen` is the size.
//! - `getsockopt` returns `EINVAL` if `optlen` is too small for the option.
//! - `setsockopt` ignores `optlen` beyond the option's natural size for
//!   backward-compatibility with old code that passes larger buffers.
//! - Options at `SOL_SOCKET` apply to all socket types.
//! - Protocol-level options apply only to sockets of the relevant protocol.
//!
//! # References
//!
//! - POSIX.1-2024: `getsockopt()`, `setsockopt()`
//! - Linux man pages: `getsockopt(2)`, `setsockopt(2)`, `socket(7)`, `tcp(7)`
//! - Linux source: `net/socket.c` (`__sys_getsockopt`, `__sys_setsockopt`)
//!   `net/core/sock.c` (`sock_getsockopt`, `sock_setsockopt`)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Option level constants
// ---------------------------------------------------------------------------

/// Generic socket-level options (applies to all socket types).
pub const SOL_SOCKET: i32 = 1;
/// TCP-level options.
pub const IPPROTO_TCP: i32 = 6;
/// UDP-level options.
pub const IPPROTO_UDP: i32 = 17;
/// IP (IPv4)-level options.
pub const IPPROTO_IP: i32 = 0;
/// IPv6-level options.
pub const IPPROTO_IPV6: i32 = 41;

// ---------------------------------------------------------------------------
// SOL_SOCKET option names
// ---------------------------------------------------------------------------

/// Allow reuse of local addresses.
pub const SO_REUSEADDR: i32 = 2;
/// Allow reuse of local port and address by multiple sockets (`SO_REUSEPORT`).
pub const SO_REUSEPORT: i32 = 15;
/// Allow transmission of broadcast messages.
pub const SO_BROADCAST: i32 = 6;
/// Report pending socket error and clear it.
pub const SO_ERROR: i32 = 4;
/// Set the socket type (read-only; use `getsockopt` only).
pub const SO_TYPE: i32 = 3;
/// Enable keep-alive probes on the connection.
pub const SO_KEEPALIVE: i32 = 9;
/// Receive buffer size in bytes.
pub const SO_RCVBUF: i32 = 8;
/// Send buffer size in bytes.
pub const SO_SNDBUF: i32 = 7;
/// Receive timeout (`struct timeval`).
pub const SO_RCVTIMEO: i32 = 20;
/// Send timeout (`struct timeval`).
pub const SO_SNDTIMEO: i32 = 21;
/// Linger on close if unsent data remains.
pub const SO_LINGER: i32 = 13;
/// Enable out-of-band data inline in the receive stream.
pub const SO_OOBINLINE: i32 = 10;
/// Return credentials of the connecting process (Unix domain sockets).
pub const SO_PEERCRED: i32 = 17;
/// Minimum number of bytes to receive before the kernel wakes a reader.
pub const SO_RCVLOWAT: i32 = 18;
/// Minimum number of bytes to send before the kernel wakes a writer.
pub const SO_SNDLOWAT: i32 = 19;
/// Allow binding to non-local addresses.
pub const SO_BINDTODEVICE: i32 = 25;
/// Mark socket for priority routing.
pub const SO_PRIORITY: i32 = 12;
/// Set the domain (address family) — read-only on Linux.
pub const SO_DOMAIN: i32 = 39;
/// Set/get protocol number — read-only.
pub const SO_PROTOCOL: i32 = 38;

// ---------------------------------------------------------------------------
// IPPROTO_TCP option names
// ---------------------------------------------------------------------------

/// Disable the Nagle algorithm (send small packets immediately).
pub const TCP_NODELAY: i32 = 1;
/// Maximum segment size.
pub const TCP_MAXSEG: i32 = 2;
/// Enable/disable TCP_CORK.
pub const TCP_CORK: i32 = 3;
/// Time to wait before closing the connection.
pub const TCP_KEEPIDLE: i32 = 4;
/// Interval between keep-alive probes.
pub const TCP_KEEPINTVL: i32 = 5;
/// Number of keep-alive probes before giving up.
pub const TCP_KEEPCNT: i32 = 6;
/// Enable/disable TCP fast open.
pub const TCP_FASTOPEN: i32 = 23;
/// User timeout (milliseconds).
pub const TCP_USER_TIMEOUT: i32 = 18;

// ---------------------------------------------------------------------------
// IPPROTO_IP option names
// ---------------------------------------------------------------------------

/// IP time-to-live.
pub const IP_TTL: i32 = 2;
/// Type of service (DSCP).
pub const IP_TOS: i32 = 1;
/// Multicast TTL.
pub const IP_MULTICAST_TTL: i32 = 33;
/// Join a multicast group.
pub const IP_ADD_MEMBERSHIP: i32 = 35;
/// Leave a multicast group.
pub const IP_DROP_MEMBERSHIP: i32 = 36;

// ---------------------------------------------------------------------------
// IPPROTO_IPV6 option names
// ---------------------------------------------------------------------------

/// Restrict socket to IPv6 only (no IPv4-mapped addresses).
pub const IPV6_V6ONLY: i32 = 26;
/// Unicast hop limit.
pub const IPV6_UNICAST_HOPS: i32 = 16;
/// Multicast hop limit.
pub const IPV6_MULTICAST_HOPS: i32 = 18;

// ---------------------------------------------------------------------------
// Option value types
// ---------------------------------------------------------------------------

/// The value of a socket option.
///
/// Most options are represented as `i32` integers, but a few use structured
/// types.  This enum covers the commonly used option value representations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptVal {
    /// Integer-valued option (the most common case).
    Int(i32),
    /// Boolean option stored as `0` or `1`.
    Bool(bool),
    /// Linger structure: `{onoff: i32, linger_sec: i32}`.
    Linger { onoff: i32, linger_sec: i32 },
    /// Timeout: seconds and microseconds.
    Timeval { sec: i64, usec: i64 },
}

impl OptVal {
    /// Return the minimum buffer size required to hold this value.
    pub const fn min_size(&self) -> usize {
        match self {
            OptVal::Int(_) | OptVal::Bool(_) => 4,
            OptVal::Linger { .. } => 8,
            OptVal::Timeval { .. } => 16,
        }
    }

    /// Extract the integer value, if the variant is `Int` or `Bool`.
    pub fn as_i32(&self) -> Option<i32> {
        match *self {
            OptVal::Int(v) => Some(v),
            OptVal::Bool(b) => Some(b as i32),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Socket option store
// ---------------------------------------------------------------------------

/// Default receive buffer size (128 KiB).
const DEFAULT_RCVBUF: i32 = 131072;
/// Default send buffer size (128 KiB).
const DEFAULT_SNDBUF: i32 = 131072;
/// Default IP TTL.
const DEFAULT_IP_TTL: i32 = 64;
/// Default TCP maximum segment size.
const DEFAULT_TCP_MAXSEG: i32 = 536;
/// Default IPv6 hop limit.
const DEFAULT_IPV6_HOPS: i32 = 64;

/// Per-socket option storage.
///
/// Holds the current value of commonly used socket options.  Options that
/// have not been explicitly set hold their POSIX/kernel defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketOptions {
    /// `SO_REUSEADDR`
    pub reuseaddr: bool,
    /// `SO_REUSEPORT`
    pub reuseport: bool,
    /// `SO_BROADCAST`
    pub broadcast: bool,
    /// `SO_KEEPALIVE`
    pub keepalive: bool,
    /// `SO_RCVBUF` (bytes)
    pub rcvbuf: i32,
    /// `SO_SNDBUF` (bytes)
    pub sndbuf: i32,
    /// `SO_OOBINLINE`
    pub oobinline: bool,
    /// `SO_PRIORITY`
    pub priority: i32,
    /// `SO_RCVTIMEO` seconds
    pub rcvtimeo_sec: i64,
    /// `SO_RCVTIMEO` microseconds
    pub rcvtimeo_usec: i64,
    /// `SO_SNDTIMEO` seconds
    pub sndtimeo_sec: i64,
    /// `SO_SNDTIMEO` microseconds
    pub sndtimeo_usec: i64,
    /// `SO_LINGER` on/off flag
    pub linger_onoff: i32,
    /// `SO_LINGER` seconds
    pub linger_sec: i32,
    /// `SO_RCVLOWAT`
    pub rcvlowat: i32,
    /// `SO_SNDLOWAT`
    pub sndlowat: i32,
    /// Pending error (read and clear via `SO_ERROR`)
    pub pending_error: i32,
    /// Socket type (read-only, set at creation)
    pub sock_type: i32,
    /// Domain / address family (read-only, set at creation)
    pub domain: i32,
    /// Protocol number (read-only, set at creation)
    pub protocol: i32,
    // TCP options
    /// `TCP_NODELAY`
    pub tcp_nodelay: bool,
    /// `TCP_MAXSEG`
    pub tcp_maxseg: i32,
    /// `TCP_CORK`
    pub tcp_cork: bool,
    /// `TCP_KEEPIDLE` (seconds)
    pub tcp_keepidle: i32,
    /// `TCP_KEEPINTVL` (seconds)
    pub tcp_keepintvl: i32,
    /// `TCP_KEEPCNT`
    pub tcp_keepcnt: i32,
    /// `TCP_USER_TIMEOUT` (milliseconds)
    pub tcp_user_timeout: i32,
    // IP options
    /// `IP_TTL`
    pub ip_ttl: i32,
    /// `IP_TOS`
    pub ip_tos: i32,
    // IPv6 options
    /// `IPV6_V6ONLY`
    pub ipv6_v6only: bool,
    /// `IPV6_UNICAST_HOPS`
    pub ipv6_unicast_hops: i32,
}

impl Default for SocketOptions {
    fn default() -> Self {
        Self {
            reuseaddr: false,
            reuseport: false,
            broadcast: false,
            keepalive: false,
            rcvbuf: DEFAULT_RCVBUF,
            sndbuf: DEFAULT_SNDBUF,
            oobinline: false,
            priority: 0,
            rcvtimeo_sec: 0,
            rcvtimeo_usec: 0,
            sndtimeo_sec: 0,
            sndtimeo_usec: 0,
            linger_onoff: 0,
            linger_sec: 0,
            rcvlowat: 1,
            sndlowat: 1,
            pending_error: 0,
            sock_type: 0,
            domain: 0,
            protocol: 0,
            tcp_nodelay: false,
            tcp_maxseg: DEFAULT_TCP_MAXSEG,
            tcp_cork: false,
            tcp_keepidle: 7200,
            tcp_keepintvl: 75,
            tcp_keepcnt: 9,
            tcp_user_timeout: 0,
            ip_ttl: DEFAULT_IP_TTL,
            ip_tos: 0,
            ipv6_v6only: false,
            ipv6_unicast_hops: DEFAULT_IPV6_HOPS,
        }
    }
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `getsockopt(2)`.
///
/// Retrieves the current value of the socket option identified by
/// `(level, optname)` from `opts`.
///
/// # Arguments
///
/// * `fd`      — Socket file descriptor (validated non-negative only).
/// * `opts`    — Current socket option store.
/// * `level`   — Protocol level (e.g., `SOL_SOCKET`, `IPPROTO_TCP`).
/// * `optname` — Option identifier.
/// * `optlen`  — Size of the caller's buffer; must be sufficient for the option.
///
/// # Errors
///
/// - `Error::InvalidArgument` — `fd < 0`, unknown `level`/`optname`, or
///   `optlen` too small (`EINVAL` / `ENOPROTOOPT`).
///
/// # POSIX conformance
///
/// Returns the option value through `OptVal`.  For read-only options (e.g.,
/// `SO_TYPE`, `SO_DOMAIN`), the value reflects the socket's immutable
/// properties set at creation time.
pub fn do_getsockopt(
    fd: i32,
    opts: &mut SocketOptions,
    level: i32,
    optname: i32,
    optlen: u32,
) -> Result<OptVal> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }

    let val = get_option(opts, level, optname)?;

    // Validate that the caller's buffer is large enough.
    if (optlen as usize) < val.min_size() {
        return Err(Error::InvalidArgument);
    }

    Ok(val)
}

/// Handler for `setsockopt(2)`.
///
/// Sets the socket option identified by `(level, optname)` in `opts` to
/// the value `optval`.
///
/// # Arguments
///
/// * `fd`      — Socket file descriptor (validated non-negative only).
/// * `opts`    — Mutable socket option store to update.
/// * `level`   — Protocol level.
/// * `optname` — Option identifier.
/// * `optval`  — New value for the option.
/// * `optlen`  — Size of `optval`; must be sufficient for the option type.
///
/// # Errors
///
/// - `Error::InvalidArgument` — `fd < 0`, unknown level/option, read-only
///   option, or value out of range (`EINVAL` / `ENOPROTOOPT`).
///
/// # POSIX conformance
///
/// Read-only options (`SO_TYPE`, `SO_ERROR`, `SO_DOMAIN`, `SO_PROTOCOL`)
/// return `ENOPROTOOPT` (mapped to `InvalidArgument`) when a set is attempted.
pub fn do_setsockopt(
    fd: i32,
    opts: &mut SocketOptions,
    level: i32,
    optname: i32,
    optval: OptVal,
    optlen: u32,
) -> Result<()> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }

    // Minimum size check.
    if (optlen as usize) < optval.min_size() {
        return Err(Error::InvalidArgument);
    }

    set_option(opts, level, optname, optval)
}

// ---------------------------------------------------------------------------
// Internal get/set dispatch
// ---------------------------------------------------------------------------

fn get_option(opts: &mut SocketOptions, level: i32, optname: i32) -> Result<OptVal> {
    match level {
        SOL_SOCKET => get_sol_socket(opts, optname),
        IPPROTO_TCP => get_tcp(opts, optname),
        IPPROTO_IP => get_ip(opts, optname),
        IPPROTO_IPV6 => get_ipv6(opts, optname),
        _ => Err(Error::InvalidArgument),
    }
}

fn set_option(opts: &mut SocketOptions, level: i32, optname: i32, val: OptVal) -> Result<()> {
    match level {
        SOL_SOCKET => set_sol_socket(opts, optname, val),
        IPPROTO_TCP => set_tcp(opts, optname, val),
        IPPROTO_IP => set_ip(opts, optname, val),
        IPPROTO_IPV6 => set_ipv6(opts, optname, val),
        _ => Err(Error::InvalidArgument),
    }
}

// --- SOL_SOCKET get ---

fn get_sol_socket(opts: &mut SocketOptions, optname: i32) -> Result<OptVal> {
    match optname {
        SO_REUSEADDR => Ok(OptVal::Bool(opts.reuseaddr)),
        SO_REUSEPORT => Ok(OptVal::Bool(opts.reuseport)),
        SO_BROADCAST => Ok(OptVal::Bool(opts.broadcast)),
        SO_KEEPALIVE => Ok(OptVal::Bool(opts.keepalive)),
        SO_RCVBUF => Ok(OptVal::Int(opts.rcvbuf)),
        SO_SNDBUF => Ok(OptVal::Int(opts.sndbuf)),
        SO_OOBINLINE => Ok(OptVal::Bool(opts.oobinline)),
        SO_PRIORITY => Ok(OptVal::Int(opts.priority)),
        SO_RCVLOWAT => Ok(OptVal::Int(opts.rcvlowat)),
        SO_SNDLOWAT => Ok(OptVal::Int(opts.sndlowat)),
        SO_LINGER => Ok(OptVal::Linger {
            onoff: opts.linger_onoff,
            linger_sec: opts.linger_sec,
        }),
        SO_RCVTIMEO => Ok(OptVal::Timeval {
            sec: opts.rcvtimeo_sec,
            usec: opts.rcvtimeo_usec,
        }),
        SO_SNDTIMEO => Ok(OptVal::Timeval {
            sec: opts.sndtimeo_sec,
            usec: opts.sndtimeo_usec,
        }),
        SO_ERROR => {
            // Read-and-clear the pending error.
            let err = opts.pending_error;
            opts.pending_error = 0;
            Ok(OptVal::Int(err))
        }
        SO_TYPE => Ok(OptVal::Int(opts.sock_type)),
        SO_DOMAIN => Ok(OptVal::Int(opts.domain)),
        SO_PROTOCOL => Ok(OptVal::Int(opts.protocol)),
        _ => Err(Error::InvalidArgument),
    }
}

// --- SOL_SOCKET set ---

fn set_sol_socket(opts: &mut SocketOptions, optname: i32, val: OptVal) -> Result<()> {
    match optname {
        SO_REUSEADDR => {
            opts.reuseaddr = bool_from_optval(val)?;
        }
        SO_REUSEPORT => {
            opts.reuseport = bool_from_optval(val)?;
        }
        SO_BROADCAST => {
            opts.broadcast = bool_from_optval(val)?;
        }
        SO_KEEPALIVE => {
            opts.keepalive = bool_from_optval(val)?;
        }
        SO_RCVBUF => {
            let v = int_from_optval(val)?;
            if v < 0 {
                return Err(Error::InvalidArgument);
            }
            opts.rcvbuf = v;
        }
        SO_SNDBUF => {
            let v = int_from_optval(val)?;
            if v < 0 {
                return Err(Error::InvalidArgument);
            }
            opts.sndbuf = v;
        }
        SO_OOBINLINE => {
            opts.oobinline = bool_from_optval(val)?;
        }
        SO_PRIORITY => {
            opts.priority = int_from_optval(val)?;
        }
        SO_RCVLOWAT => {
            let v = int_from_optval(val)?;
            if v <= 0 {
                return Err(Error::InvalidArgument);
            }
            opts.rcvlowat = v;
        }
        SO_SNDLOWAT => {
            let v = int_from_optval(val)?;
            if v <= 0 {
                return Err(Error::InvalidArgument);
            }
            opts.sndlowat = v;
        }
        SO_LINGER => {
            if let OptVal::Linger { onoff, linger_sec } = val {
                opts.linger_onoff = onoff;
                opts.linger_sec = linger_sec;
            } else {
                return Err(Error::InvalidArgument);
            }
        }
        SO_RCVTIMEO => {
            if let OptVal::Timeval { sec, usec } = val {
                opts.rcvtimeo_sec = sec;
                opts.rcvtimeo_usec = usec;
            } else {
                return Err(Error::InvalidArgument);
            }
        }
        SO_SNDTIMEO => {
            if let OptVal::Timeval { sec, usec } = val {
                opts.sndtimeo_sec = sec;
                opts.sndtimeo_usec = usec;
            } else {
                return Err(Error::InvalidArgument);
            }
        }
        // Read-only options.
        SO_ERROR | SO_TYPE | SO_DOMAIN | SO_PROTOCOL => {
            return Err(Error::InvalidArgument);
        }
        _ => return Err(Error::InvalidArgument),
    }
    Ok(())
}

// --- IPPROTO_TCP get ---

fn get_tcp(opts: &SocketOptions, optname: i32) -> Result<OptVal> {
    match optname {
        TCP_NODELAY => Ok(OptVal::Bool(opts.tcp_nodelay)),
        TCP_MAXSEG => Ok(OptVal::Int(opts.tcp_maxseg)),
        TCP_CORK => Ok(OptVal::Bool(opts.tcp_cork)),
        TCP_KEEPIDLE => Ok(OptVal::Int(opts.tcp_keepidle)),
        TCP_KEEPINTVL => Ok(OptVal::Int(opts.tcp_keepintvl)),
        TCP_KEEPCNT => Ok(OptVal::Int(opts.tcp_keepcnt)),
        TCP_USER_TIMEOUT => Ok(OptVal::Int(opts.tcp_user_timeout)),
        _ => Err(Error::InvalidArgument),
    }
}

// --- IPPROTO_TCP set ---

fn set_tcp(opts: &mut SocketOptions, optname: i32, val: OptVal) -> Result<()> {
    match optname {
        TCP_NODELAY => {
            opts.tcp_nodelay = bool_from_optval(val)?;
        }
        TCP_MAXSEG => {
            let v = int_from_optval(val)?;
            if v < 64 || v > 65535 {
                return Err(Error::InvalidArgument);
            }
            opts.tcp_maxseg = v;
        }
        TCP_CORK => {
            opts.tcp_cork = bool_from_optval(val)?;
        }
        TCP_KEEPIDLE => {
            let v = int_from_optval(val)?;
            if v <= 0 {
                return Err(Error::InvalidArgument);
            }
            opts.tcp_keepidle = v;
        }
        TCP_KEEPINTVL => {
            let v = int_from_optval(val)?;
            if v <= 0 {
                return Err(Error::InvalidArgument);
            }
            opts.tcp_keepintvl = v;
        }
        TCP_KEEPCNT => {
            let v = int_from_optval(val)?;
            if v <= 0 {
                return Err(Error::InvalidArgument);
            }
            opts.tcp_keepcnt = v;
        }
        TCP_USER_TIMEOUT => {
            opts.tcp_user_timeout = int_from_optval(val)?;
        }
        _ => return Err(Error::InvalidArgument),
    }
    Ok(())
}

// --- IPPROTO_IP get ---

fn get_ip(opts: &SocketOptions, optname: i32) -> Result<OptVal> {
    match optname {
        IP_TTL => Ok(OptVal::Int(opts.ip_ttl)),
        IP_TOS => Ok(OptVal::Int(opts.ip_tos)),
        _ => Err(Error::InvalidArgument),
    }
}

// --- IPPROTO_IP set ---

fn set_ip(opts: &mut SocketOptions, optname: i32, val: OptVal) -> Result<()> {
    match optname {
        IP_TTL => {
            let v = int_from_optval(val)?;
            if !(0..=255).contains(&v) {
                return Err(Error::InvalidArgument);
            }
            opts.ip_ttl = v;
        }
        IP_TOS => {
            let v = int_from_optval(val)?;
            if !(0..=255).contains(&v) {
                return Err(Error::InvalidArgument);
            }
            opts.ip_tos = v;
        }
        _ => return Err(Error::InvalidArgument),
    }
    Ok(())
}

// --- IPPROTO_IPV6 get ---

fn get_ipv6(opts: &SocketOptions, optname: i32) -> Result<OptVal> {
    match optname {
        IPV6_V6ONLY => Ok(OptVal::Bool(opts.ipv6_v6only)),
        IPV6_UNICAST_HOPS => Ok(OptVal::Int(opts.ipv6_unicast_hops)),
        IPV6_MULTICAST_HOPS => Ok(OptVal::Int(opts.ipv6_unicast_hops)), // shared for simplicity
        _ => Err(Error::InvalidArgument),
    }
}

// --- IPPROTO_IPV6 set ---

fn set_ipv6(opts: &mut SocketOptions, optname: i32, val: OptVal) -> Result<()> {
    match optname {
        IPV6_V6ONLY => {
            opts.ipv6_v6only = bool_from_optval(val)?;
        }
        IPV6_UNICAST_HOPS => {
            let v = int_from_optval(val)?;
            if v < -1 || v > 255 {
                return Err(Error::InvalidArgument);
            }
            opts.ipv6_unicast_hops = if v == -1 { DEFAULT_IPV6_HOPS } else { v };
        }
        IPV6_MULTICAST_HOPS => {
            let v = int_from_optval(val)?;
            if v < -1 || v > 255 {
                return Err(Error::InvalidArgument);
            }
            // Stored in unicast_hops for simplicity in this stub.
            opts.ipv6_unicast_hops = if v == -1 { DEFAULT_IPV6_HOPS } else { v };
        }
        _ => return Err(Error::InvalidArgument),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helper extractors
// ---------------------------------------------------------------------------

/// Extract a boolean from an `OptVal`, accepting `Int` or `Bool`.
fn bool_from_optval(val: OptVal) -> Result<bool> {
    match val {
        OptVal::Bool(b) => Ok(b),
        OptVal::Int(v) => Ok(v != 0),
        _ => Err(Error::InvalidArgument),
    }
}

/// Extract an `i32` from an `OptVal`, accepting `Int` or `Bool`.
fn int_from_optval(val: OptVal) -> Result<i32> {
    match val {
        OptVal::Int(v) => Ok(v),
        OptVal::Bool(b) => Ok(b as i32),
        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> SocketOptions {
        SocketOptions::default()
    }

    // --- do_getsockopt ---

    #[test]
    fn getsockopt_rejects_negative_fd() {
        let mut o = opts();
        assert_eq!(
            do_getsockopt(-1, &mut o, SOL_SOCKET, SO_REUSEADDR, 4),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn getsockopt_rejects_too_small_optlen() {
        let mut o = opts();
        assert_eq!(
            do_getsockopt(3, &mut o, SOL_SOCKET, SO_RCVBUF, 2),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn getsockopt_reuseaddr_default_false() {
        let mut o = opts();
        let v = do_getsockopt(3, &mut o, SOL_SOCKET, SO_REUSEADDR, 4).unwrap();
        assert_eq!(v, OptVal::Bool(false));
    }

    #[test]
    fn getsockopt_rcvbuf_default() {
        let mut o = opts();
        let v = do_getsockopt(3, &mut o, SOL_SOCKET, SO_RCVBUF, 4).unwrap();
        assert_eq!(v, OptVal::Int(DEFAULT_RCVBUF));
    }

    #[test]
    fn getsockopt_so_error_clears_pending() {
        let mut o = opts();
        o.pending_error = 111; // ECONNREFUSED
        let v = do_getsockopt(3, &mut o, SOL_SOCKET, SO_ERROR, 4).unwrap();
        assert_eq!(v, OptVal::Int(111));
        // Second read should return 0.
        let v2 = do_getsockopt(3, &mut o, SOL_SOCKET, SO_ERROR, 4).unwrap();
        assert_eq!(v2, OptVal::Int(0));
    }

    #[test]
    fn getsockopt_unknown_level_returns_einval() {
        let mut o = opts();
        assert_eq!(
            do_getsockopt(3, &mut o, 999, SO_REUSEADDR, 4),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn getsockopt_unknown_optname_returns_einval() {
        let mut o = opts();
        assert_eq!(
            do_getsockopt(3, &mut o, SOL_SOCKET, 9999, 4),
            Err(Error::InvalidArgument)
        );
    }

    // --- do_setsockopt ---

    #[test]
    fn setsockopt_rejects_negative_fd() {
        let mut o = opts();
        assert_eq!(
            do_setsockopt(-1, &mut o, SOL_SOCKET, SO_REUSEADDR, OptVal::Bool(true), 4),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn setsockopt_reuseaddr() {
        let mut o = opts();
        do_setsockopt(3, &mut o, SOL_SOCKET, SO_REUSEADDR, OptVal::Bool(true), 4).unwrap();
        assert!(o.reuseaddr);
        let v = do_getsockopt(3, &mut o, SOL_SOCKET, SO_REUSEADDR, 4).unwrap();
        assert_eq!(v, OptVal::Bool(true));
    }

    #[test]
    fn setsockopt_rcvbuf() {
        let mut o = opts();
        do_setsockopt(3, &mut o, SOL_SOCKET, SO_RCVBUF, OptVal::Int(65536), 4).unwrap();
        assert_eq!(o.rcvbuf, 65536);
    }

    #[test]
    fn setsockopt_rcvbuf_negative_rejected() {
        let mut o = opts();
        assert_eq!(
            do_setsockopt(3, &mut o, SOL_SOCKET, SO_RCVBUF, OptVal::Int(-1), 4),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn setsockopt_linger() {
        let mut o = opts();
        do_setsockopt(
            3,
            &mut o,
            SOL_SOCKET,
            SO_LINGER,
            OptVal::Linger {
                onoff: 1,
                linger_sec: 5,
            },
            8,
        )
        .unwrap();
        assert_eq!(o.linger_onoff, 1);
        assert_eq!(o.linger_sec, 5);
    }

    #[test]
    fn setsockopt_readonly_so_type_rejected() {
        let mut o = opts();
        assert_eq!(
            do_setsockopt(3, &mut o, SOL_SOCKET, SO_TYPE, OptVal::Int(1), 4),
            Err(Error::InvalidArgument)
        );
    }

    // --- TCP options ---

    #[test]
    fn setsockopt_tcp_nodelay() {
        let mut o = opts();
        do_setsockopt(3, &mut o, IPPROTO_TCP, TCP_NODELAY, OptVal::Bool(true), 4).unwrap();
        assert!(o.tcp_nodelay);
        let v = do_getsockopt(3, &mut o, IPPROTO_TCP, TCP_NODELAY, 4).unwrap();
        assert_eq!(v, OptVal::Bool(true));
    }

    #[test]
    fn setsockopt_tcp_maxseg_out_of_range() {
        let mut o = opts();
        assert_eq!(
            do_setsockopt(3, &mut o, IPPROTO_TCP, TCP_MAXSEG, OptVal::Int(10), 4),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn setsockopt_tcp_keepidle() {
        let mut o = opts();
        do_setsockopt(3, &mut o, IPPROTO_TCP, TCP_KEEPIDLE, OptVal::Int(300), 4).unwrap();
        assert_eq!(o.tcp_keepidle, 300);
    }

    // --- IP options ---

    #[test]
    fn setsockopt_ip_ttl() {
        let mut o = opts();
        do_setsockopt(3, &mut o, IPPROTO_IP, IP_TTL, OptVal::Int(128), 4).unwrap();
        assert_eq!(o.ip_ttl, 128);
    }

    #[test]
    fn setsockopt_ip_ttl_out_of_range() {
        let mut o = opts();
        assert_eq!(
            do_setsockopt(3, &mut o, IPPROTO_IP, IP_TTL, OptVal::Int(300), 4),
            Err(Error::InvalidArgument)
        );
    }

    // --- IPv6 options ---

    #[test]
    fn setsockopt_ipv6_v6only() {
        let mut o = opts();
        do_setsockopt(3, &mut o, IPPROTO_IPV6, IPV6_V6ONLY, OptVal::Bool(true), 4).unwrap();
        assert!(o.ipv6_v6only);
        let v = do_getsockopt(3, &mut o, IPPROTO_IPV6, IPV6_V6ONLY, 4).unwrap();
        assert_eq!(v, OptVal::Bool(true));
    }

    #[test]
    fn setsockopt_ipv6_hops_minus_one_resets_default() {
        let mut o = opts();
        o.ipv6_unicast_hops = 100;
        do_setsockopt(
            3,
            &mut o,
            IPPROTO_IPV6,
            IPV6_UNICAST_HOPS,
            OptVal::Int(-1),
            4,
        )
        .unwrap();
        assert_eq!(o.ipv6_unicast_hops, DEFAULT_IPV6_HOPS);
    }
}
