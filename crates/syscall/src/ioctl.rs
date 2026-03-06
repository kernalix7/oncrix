// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `ioctl(2)` syscall dispatcher — device control operations.
//!
//! Provides ioctl encoding/decoding helpers, common ioctl number
//! constants, and a registry-based dispatcher ([`do_ioctl`]) that
//! fans out to terminal, file, and device-specific handlers.
//!
//! Supported ioctl categories:
//! - Terminal ioctls: `TCGETS`, `TCSETS`, `TIOCGWINSZ`, `TIOCSWINSZ`
//! - File ioctls: `FIONREAD`, `FIONBIO`, `FIOCLEX`, `FIONCLEX`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// ioctl encoding constants
// ---------------------------------------------------------------------------

/// No direction (command only, no data transfer).
pub const IOC_NONE: u8 = 0;
/// Write direction (user → kernel).
pub const IOC_WRITE: u8 = 1;
/// Read direction (kernel → user).
pub const IOC_READ: u8 = 2;

/// Number of bits for the ioctl number field.
const IOC_NRBITS: u32 = 8;
/// Number of bits for the ioctl type field.
const IOC_TYPEBITS: u32 = 8;
/// Number of bits for the ioctl size field.
const IOC_SIZEBITS: u32 = 14;

/// Bit shift for the number field.
const IOC_NRSHIFT: u32 = 0;
/// Bit shift for the type field.
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
/// Bit shift for the size field.
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
/// Bit shift for the direction field.
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;

// ---------------------------------------------------------------------------
// ioctl encoding helpers
// ---------------------------------------------------------------------------

/// Encode an ioctl command number from direction, type, number, and size.
pub const fn _ioc(dir: u8, ty: u8, nr: u8, size: u16) -> u32 {
    ((dir as u32) << IOC_DIRSHIFT)
        | ((ty as u32) << IOC_TYPESHIFT)
        | ((nr as u32) << IOC_NRSHIFT)
        | ((size as u32) << IOC_SIZESHIFT)
}

/// Encode an ioctl command with no data transfer.
pub const fn _io(ty: u8, nr: u8) -> u32 {
    _ioc(IOC_NONE, ty, nr, 0)
}

/// Encode a read ioctl command (kernel → user).
pub const fn _ior(ty: u8, nr: u8, size: u16) -> u32 {
    _ioc(IOC_READ, ty, nr, size)
}

/// Encode a write ioctl command (user → kernel).
pub const fn _iow(ty: u8, nr: u8, size: u16) -> u32 {
    _ioc(IOC_WRITE, ty, nr, size)
}

/// Encode a read/write ioctl command.
pub const fn _iowr(ty: u8, nr: u8, size: u16) -> u32 {
    _ioc(IOC_READ | IOC_WRITE, ty, nr, size)
}

/// Decode an ioctl command into `(direction, type, number, size)`.
pub const fn decode_ioctl(cmd: u32) -> (u8, u8, u8, u16) {
    let dir = ((cmd >> IOC_DIRSHIFT) & 0x3) as u8;
    let ty = ((cmd >> IOC_TYPESHIFT) & 0xFF) as u8;
    let nr = ((cmd >> IOC_NRSHIFT) & 0xFF) as u8;
    let size = ((cmd >> IOC_SIZESHIFT) & 0x3FFF) as u16;
    (dir, ty, nr, size)
}

// ---------------------------------------------------------------------------
// Common ioctl numbers — terminal
// ---------------------------------------------------------------------------

/// Get terminal attributes (`struct termios`).
pub const TCGETS: u32 = 0x5401;
/// Set terminal attributes (`struct termios`).
pub const TCSETS: u32 = 0x5402;
/// Get window size (`struct winsize`).
pub const TIOCGWINSZ: u32 = 0x5413;
/// Set window size (`struct winsize`).
pub const TIOCSWINSZ: u32 = 0x5414;

// ---------------------------------------------------------------------------
// Common ioctl numbers — file
// ---------------------------------------------------------------------------

/// Get the number of bytes available for reading.
pub const FIONREAD: u32 = 0x541B;
/// Set or clear non-blocking I/O mode.
pub const FIONBIO: u32 = 0x5421;
/// Set close-on-exec flag.
pub const FIOCLEX: u32 = 0x5451;
/// Clear close-on-exec flag.
pub const FIONCLEX: u32 = 0x5450;

// ---------------------------------------------------------------------------
// Winsize — terminal window dimensions
// ---------------------------------------------------------------------------

/// Terminal window size structure (`struct winsize`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Winsize {
    /// Number of rows.
    pub ws_row: u16,
    /// Number of columns.
    pub ws_col: u16,
    /// Horizontal pixel size (unused by most applications).
    pub ws_xpixel: u16,
    /// Vertical pixel size (unused by most applications).
    pub ws_ypixel: u16,
}

impl Winsize {
    /// Create a new window size with the given dimensions.
    pub const fn new(rows: u16, cols: u16) -> Self {
        Self {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Termios — terminal I/O settings
// ---------------------------------------------------------------------------

/// Terminal I/O settings structure (`struct termios`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Termios {
    /// Input mode flags.
    pub c_iflag: u32,
    /// Output mode flags.
    pub c_oflag: u32,
    /// Control mode flags.
    pub c_cflag: u32,
    /// Local mode flags.
    pub c_lflag: u32,
    /// Control characters.
    pub c_cc: [u8; 32],
    /// Input baud rate.
    pub c_ispeed: u32,
    /// Output baud rate.
    pub c_ospeed: u32,
}

// ---------------------------------------------------------------------------
// IoctlHandler — registered ioctl command handler
// ---------------------------------------------------------------------------

/// Maximum number of registered ioctl handlers.
const MAX_IOCTL_HANDLERS: usize = 64;

/// Maximum length of an ioctl handler name.
const IOCTL_NAME_BUF: usize = 32;

/// A registered ioctl command handler entry.
#[derive(Debug, Clone, Copy)]
pub struct IoctlHandler {
    /// The ioctl command number this handler serves.
    pub cmd: u32,
    /// Human-readable name of the handler (null-padded).
    pub name: [u8; IOCTL_NAME_BUF],
    /// Length of the name in bytes (excluding padding).
    pub name_len: usize,
    /// Whether this handler slot is active.
    pub active: bool,
}

impl Default for IoctlHandler {
    fn default() -> Self {
        Self {
            cmd: 0,
            name: [0u8; IOCTL_NAME_BUF],
            name_len: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// IoctlRegistry — dynamic handler registration
// ---------------------------------------------------------------------------

/// Registry of ioctl command handlers.
///
/// Supports up to [`MAX_IOCTL_HANDLERS`] (64) concurrent registrations.
pub struct IoctlRegistry {
    /// Fixed array of handler slots.
    handlers: [IoctlHandler; MAX_IOCTL_HANDLERS],
    /// Number of active handlers.
    count: usize,
}

impl Default for IoctlRegistry {
    fn default() -> Self {
        Self {
            handlers: [IoctlHandler::default(); MAX_IOCTL_HANDLERS],
            count: 0,
        }
    }
}

impl IoctlRegistry {
    /// Register a new ioctl handler for `cmd` with the given `name`.
    ///
    /// Returns `Error::InvalidArgument` if the name is empty or too long,
    /// `Error::AlreadyExists` if `cmd` is already registered, or
    /// `Error::OutOfMemory` if the registry is full.
    pub fn register_handler(&mut self, cmd: u32, name: &[u8]) -> Result<()> {
        if name.is_empty() || name.len() > IOCTL_NAME_BUF {
            return Err(Error::InvalidArgument);
        }

        // Check for duplicate registration.
        if self.handlers.iter().any(|h| h.active && h.cmd == cmd) {
            return Err(Error::AlreadyExists);
        }

        // Find the first inactive slot.
        let slot = self
            .handlers
            .iter_mut()
            .find(|h| !h.active)
            .ok_or(Error::OutOfMemory)?;

        slot.cmd = cmd;
        slot.name = [0u8; IOCTL_NAME_BUF];
        let len = name.len().min(IOCTL_NAME_BUF);
        slot.name[..len].copy_from_slice(&name[..len]);
        slot.name_len = len;
        slot.active = true;
        self.count = self.count.saturating_add(1);

        Ok(())
    }

    /// Unregister the handler for `cmd`.
    ///
    /// Returns `Error::NotFound` if no active handler matches `cmd`.
    pub fn unregister_handler(&mut self, cmd: u32) -> Result<()> {
        let slot = self
            .handlers
            .iter_mut()
            .find(|h| h.active && h.cmd == cmd)
            .ok_or(Error::NotFound)?;

        slot.active = false;
        slot.cmd = 0;
        slot.name = [0u8; IOCTL_NAME_BUF];
        slot.name_len = 0;
        self.count = self.count.saturating_sub(1);

        Ok(())
    }

    /// Check whether `cmd` has an active handler registered.
    pub fn is_registered(&self, cmd: u32) -> bool {
        self.handlers.iter().any(|h| h.active && h.cmd == cmd)
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate that the file descriptor is non-negative.
fn validate_fd(fd: i32) -> Result<()> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Syscall dispatcher
// ---------------------------------------------------------------------------

/// Top-level `ioctl(2)` syscall handler.
///
/// Dispatches to the appropriate handler based on the ioctl command
/// `cmd`. The `arg` parameter is command-specific (often a pointer
/// to a user-space structure or a scalar value).
///
/// # Returns
///
/// - `0` on success for most operations.
/// - A positive value for query operations (e.g., `FIONREAD`).
/// - `Error::InvalidArgument` for invalid file descriptors.
/// - `Error::NotImplemented` for unrecognised commands.
pub fn do_ioctl(fd: i32, cmd: u32, arg: u64) -> Result<u64> {
    validate_fd(fd)?;

    // Suppress unused-variable warning; real implementation dereferences
    // `arg` as a user pointer based on the command.
    let _ = arg;

    match cmd {
        // ── Terminal ioctls ──────────────────────────────────────
        TCGETS => {
            // Stub: copy current termios to user buffer at `arg`.
            Err(Error::NotImplemented)
        }
        TCSETS => {
            // Stub: set termios from user buffer at `arg`.
            Err(Error::NotImplemented)
        }
        TIOCGWINSZ => {
            // Stub: copy current winsize to user buffer at `arg`.
            Err(Error::NotImplemented)
        }
        TIOCSWINSZ => {
            // Stub: set winsize from user buffer at `arg`.
            Err(Error::NotImplemented)
        }

        // ── File ioctls ──────────────────────────────────────────
        FIONREAD => {
            // Stub: return number of bytes available for reading.
            Err(Error::NotImplemented)
        }
        FIONBIO => {
            // Stub: set or clear non-blocking I/O based on `arg`.
            Err(Error::NotImplemented)
        }
        FIOCLEX => {
            // Stub: set close-on-exec flag on `fd`.
            Err(Error::NotImplemented)
        }
        FIONCLEX => {
            // Stub: clear close-on-exec flag on `fd`.
            Err(Error::NotImplemented)
        }

        // ── Unknown ──────────────────────────────────────────────
        _ => Err(Error::NotImplemented),
    }
}
