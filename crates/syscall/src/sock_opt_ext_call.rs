// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended socket option handling: `SOL_SOCKET` level options.
//!
//! Provides validation and dispatch for the generic socket-level options
//! accessible via `getsockopt(2)` / `setsockopt(2)` at level `SOL_SOCKET`.
//! Protocol-specific options (IPPROTO_TCP, IPPROTO_UDP, …) are handled
//! elsewhere.
//!
//! # POSIX reference
//!
//! POSIX.1-2024 §getsockopt, §setsockopt — `<sys/socket.h>`.
//!
//! # References
//!
//! - Linux: `net/core/sock.c` `sock_setsockopt()`
//! - `socket(7)`, `getsockopt(2)`, `setsockopt(2)` man pages

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// SOL_SOCKET option constants
// ---------------------------------------------------------------------------

/// Level for socket-level options.
pub const SOL_SOCKET: i32 = 1;

/// Enable debug info recording.
pub const SO_DEBUG: i32 = 1;
/// Allow reuse of local addresses.
pub const SO_REUSEADDR: i32 = 2;
/// Keep connections alive.
pub const SO_KEEPALIVE: i32 = 9;
/// Allow sending of broadcast messages.
pub const SO_BROADCAST: i32 = 6;
/// Do not route: send directly to interface.
pub const SO_DONTROUTE: i32 = 5;
/// Permit sending of out-of-band data.
pub const SO_OOBINLINE: i32 = 10;
/// Linger on close if data present.
pub const SO_LINGER: i32 = 13;
/// Receive buffer size.
pub const SO_RCVBUF: i32 = 8;
/// Send buffer size.
pub const SO_SNDBUF: i32 = 7;
/// Receive low-water mark.
pub const SO_RCVLOWAT: i32 = 18;
/// Send low-water mark.
pub const SO_SNDLOWAT: i32 = 19;
/// Receive timeout.
pub const SO_RCVTIMEO: i32 = 20;
/// Send timeout.
pub const SO_SNDTIMEO: i32 = 21;
/// Get socket type.
pub const SO_TYPE: i32 = 3;
/// Get socket error and clear.
pub const SO_ERROR: i32 = 4;
/// Allow local port reuse.
pub const SO_REUSEPORT: i32 = 15;
/// Bind to a network device.
pub const SO_BINDTODEVICE: i32 = 25;
/// Mark socket for routing.
pub const SO_MARK: i32 = 36;
/// Non-blocking I/O.
pub const SO_DOMAIN: i32 = 39;
/// Protocol family.
pub const SO_PROTOCOL: i32 = 38;

/// Maximum buffer size the kernel will accept.
const MAX_SOCK_BUF: usize = 64 * 1024 * 1024; // 64 MiB

// ---------------------------------------------------------------------------
// SolSocketOptions — validated SOL_SOCKET option state
// ---------------------------------------------------------------------------

/// State of all tracked `SOL_SOCKET` options for one socket.
#[derive(Debug, Clone, Copy)]
pub struct SolSocketOptions {
    /// `SO_REUSEADDR`.
    pub reuse_addr: bool,
    /// `SO_REUSEPORT`.
    pub reuse_port: bool,
    /// `SO_KEEPALIVE`.
    pub keepalive: bool,
    /// `SO_BROADCAST`.
    pub broadcast: bool,
    /// `SO_DONTROUTE`.
    pub dontroute: bool,
    /// `SO_OOBINLINE`.
    pub oobinline: bool,
    /// `SO_DEBUG`.
    pub debug: bool,
    /// `SO_RCVBUF` (bytes).
    pub rcvbuf: usize,
    /// `SO_SNDBUF` (bytes).
    pub sndbuf: usize,
    /// `SO_RCVLOWAT`.
    pub rcvlowat: i32,
    /// `SO_SNDLOWAT`.
    pub sndlowat: i32,
    /// `SO_MARK`.
    pub mark: u32,
    /// Pending socket error (cleared after each read).
    pub error: i32,
    /// `SO_TYPE` — socket type (read-only after creation).
    pub sock_type: i32,
    /// `SO_DOMAIN` — address family (read-only after creation).
    pub domain: i32,
    /// `SO_PROTOCOL` — protocol (read-only after creation).
    pub protocol: i32,
}

impl Default for SolSocketOptions {
    fn default() -> Self {
        Self {
            reuse_addr: false,
            reuse_port: false,
            keepalive: false,
            broadcast: false,
            dontroute: false,
            oobinline: false,
            debug: false,
            rcvbuf: 87380,
            sndbuf: 16384,
            rcvlowat: 1,
            sndlowat: 1,
            mark: 0,
            error: 0,
            sock_type: 0,
            domain: 0,
            protocol: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// SocketOptionValue — typed option value
// ---------------------------------------------------------------------------

/// Typed socket option value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketOptionValue {
    /// Boolean option (stored as `i32`: 0 = false, non-zero = true).
    Bool(bool),
    /// Integer option.
    Int(i32),
    /// Unsigned 32-bit integer.
    U32(u32),
    /// Size in bytes (buffer sizes).
    Size(usize),
}

// ---------------------------------------------------------------------------
// setsockopt_sol_socket — set a SOL_SOCKET option
// ---------------------------------------------------------------------------

/// Apply a `SOL_SOCKET` option set.
///
/// # Arguments
///
/// * `opts`    — Option state to modify.
/// * `optname` — `SO_*` constant.
/// * `val`     — Option value.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — unrecognised option or out-of-range value.
/// * [`Error::PermissionDenied`] — read-only option.
pub fn setsockopt_sol_socket(
    opts: &mut SolSocketOptions,
    optname: i32,
    val: &SocketOptionValue,
) -> Result<()> {
    match optname {
        SO_REUSEADDR => {
            opts.reuse_addr = bool_val(val)?;
        }
        SO_REUSEPORT => {
            opts.reuse_port = bool_val(val)?;
        }
        SO_KEEPALIVE => {
            opts.keepalive = bool_val(val)?;
        }
        SO_BROADCAST => {
            opts.broadcast = bool_val(val)?;
        }
        SO_DONTROUTE => {
            opts.dontroute = bool_val(val)?;
        }
        SO_OOBINLINE => {
            opts.oobinline = bool_val(val)?;
        }
        SO_DEBUG => {
            opts.debug = bool_val(val)?;
        }
        SO_RCVBUF => {
            let sz = size_val(val)?;
            if sz > MAX_SOCK_BUF {
                return Err(Error::InvalidArgument);
            }
            opts.rcvbuf = sz;
        }
        SO_SNDBUF => {
            let sz = size_val(val)?;
            if sz > MAX_SOCK_BUF {
                return Err(Error::InvalidArgument);
            }
            opts.sndbuf = sz;
        }
        SO_RCVLOWAT => {
            let v = int_val(val)?;
            if v < 0 {
                return Err(Error::InvalidArgument);
            }
            opts.rcvlowat = v;
        }
        SO_SNDLOWAT => {
            let v = int_val(val)?;
            if v < 0 {
                return Err(Error::InvalidArgument);
            }
            opts.sndlowat = v;
        }
        SO_MARK => {
            let v = u32_val(val)?;
            opts.mark = v;
        }
        // Read-only options.
        SO_TYPE | SO_ERROR | SO_DOMAIN | SO_PROTOCOL => {
            return Err(Error::PermissionDenied);
        }
        _ => return Err(Error::InvalidArgument),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// getsockopt_sol_socket — get a SOL_SOCKET option
// ---------------------------------------------------------------------------

/// Read a `SOL_SOCKET` option.
///
/// # Errors
///
/// [`Error::InvalidArgument`] for unrecognised option names.
pub fn getsockopt_sol_socket(opts: &SolSocketOptions, optname: i32) -> Result<SocketOptionValue> {
    match optname {
        SO_REUSEADDR => Ok(SocketOptionValue::Bool(opts.reuse_addr)),
        SO_REUSEPORT => Ok(SocketOptionValue::Bool(opts.reuse_port)),
        SO_KEEPALIVE => Ok(SocketOptionValue::Bool(opts.keepalive)),
        SO_BROADCAST => Ok(SocketOptionValue::Bool(opts.broadcast)),
        SO_DONTROUTE => Ok(SocketOptionValue::Bool(opts.dontroute)),
        SO_OOBINLINE => Ok(SocketOptionValue::Bool(opts.oobinline)),
        SO_DEBUG => Ok(SocketOptionValue::Bool(opts.debug)),
        SO_RCVBUF => Ok(SocketOptionValue::Size(opts.rcvbuf)),
        SO_SNDBUF => Ok(SocketOptionValue::Size(opts.sndbuf)),
        SO_RCVLOWAT => Ok(SocketOptionValue::Int(opts.rcvlowat)),
        SO_SNDLOWAT => Ok(SocketOptionValue::Int(opts.sndlowat)),
        SO_MARK => Ok(SocketOptionValue::U32(opts.mark)),
        SO_ERROR => Ok(SocketOptionValue::Int(opts.error)),
        SO_TYPE => Ok(SocketOptionValue::Int(opts.sock_type)),
        SO_DOMAIN => Ok(SocketOptionValue::Int(opts.domain)),
        SO_PROTOCOL => Ok(SocketOptionValue::Int(opts.protocol)),
        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// Helper extractors
// ---------------------------------------------------------------------------

fn bool_val(v: &SocketOptionValue) -> Result<bool> {
    match v {
        SocketOptionValue::Bool(b) => Ok(*b),
        SocketOptionValue::Int(i) => Ok(*i != 0),
        _ => Err(Error::InvalidArgument),
    }
}

fn int_val(v: &SocketOptionValue) -> Result<i32> {
    match v {
        SocketOptionValue::Int(i) => Ok(*i),
        _ => Err(Error::InvalidArgument),
    }
}

fn u32_val(v: &SocketOptionValue) -> Result<u32> {
    match v {
        SocketOptionValue::U32(u) => Ok(*u),
        SocketOptionValue::Int(i) if *i >= 0 => Ok(*i as u32),
        _ => Err(Error::InvalidArgument),
    }
}

fn size_val(v: &SocketOptionValue) -> Result<usize> {
    match v {
        SocketOptionValue::Size(s) => Ok(*s),
        SocketOptionValue::Int(i) if *i >= 0 => Ok(*i as usize),
        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_reuseaddr() {
        let mut opts = SolSocketOptions::default();
        setsockopt_sol_socket(&mut opts, SO_REUSEADDR, &SocketOptionValue::Bool(true)).unwrap();
        assert!(opts.reuse_addr);
        let v = getsockopt_sol_socket(&opts, SO_REUSEADDR).unwrap();
        assert_eq!(v, SocketOptionValue::Bool(true));
    }

    #[test]
    fn set_rcvbuf() {
        let mut opts = SolSocketOptions::default();
        setsockopt_sol_socket(&mut opts, SO_RCVBUF, &SocketOptionValue::Size(65536)).unwrap();
        assert_eq!(opts.rcvbuf, 65536);
    }

    #[test]
    fn rcvbuf_too_large() {
        let mut opts = SolSocketOptions::default();
        assert_eq!(
            setsockopt_sol_socket(&mut opts, SO_RCVBUF, &SocketOptionValue::Size(usize::MAX)),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn readonly_so_type() {
        let mut opts = SolSocketOptions::default();
        assert_eq!(
            setsockopt_sol_socket(&mut opts, SO_TYPE, &SocketOptionValue::Int(1)),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn get_error() {
        let mut opts = SolSocketOptions::default();
        opts.error = 111;
        let v = getsockopt_sol_socket(&opts, SO_ERROR).unwrap();
        assert_eq!(v, SocketOptionValue::Int(111));
    }

    #[test]
    fn unknown_option() {
        let mut opts = SolSocketOptions::default();
        assert_eq!(
            setsockopt_sol_socket(&mut opts, 9999, &SocketOptionValue::Bool(false)),
            Err(Error::InvalidArgument)
        );
    }
}
