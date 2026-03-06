// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Generic `ioctl` dispatch handler.
//!
//! Implements `ioctl(2)` argument decoding and dispatching per the Linux
//! ioctl(2) ABI. The ioctl command number encodes direction, type, number,
//! and size, allowing type-safe dispatch without a central switch explosion.
//!
//! Handled commands include FIONREAD, FIONBIO, FIOCLEX, FIONCLEX,
//! TIOCGWINSZ, and TIOCSWINSZ.
//!
//! # References
//!
//! - Linux man pages: `ioctl(2)`, `ioctl_tty(4)`, `ioctl_ficlonerange(2)`
//! - Linux include/uapi/asm-generic/ioctl.h

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// ioctl command encoding (Linux _IOC macro ABI)
// ---------------------------------------------------------------------------

/// Direction: no data transfer.
pub const IOC_NONE: u32 = 0;
/// Direction: write to device (data goes from user to kernel).
pub const IOC_WRITE: u32 = 1;
/// Direction: read from device (data comes from kernel to user).
pub const IOC_READ: u32 = 2;

/// Bit positions for each field within the ioctl command word.
const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;
const IOC_DIRBITS: u32 = 2;

const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;

const IOC_NRMASK: u32 = (1 << IOC_NRBITS) - 1;
const IOC_TYPEMASK: u32 = (1 << IOC_TYPEBITS) - 1;
const IOC_SIZEMASK: u32 = (1 << IOC_SIZEBITS) - 1;
const IOC_DIRMASK: u32 = (1 << IOC_DIRBITS) - 1;

/// Construct an ioctl command number.
pub const fn ioc(dir: u32, typ: u8, nr: u8, size: usize) -> u32 {
    (dir << IOC_DIRSHIFT)
        | ((typ as u32) << IOC_TYPESHIFT)
        | ((nr as u32) << IOC_NRSHIFT)
        | ((size as u32) << IOC_SIZESHIFT)
}

/// Extract the direction field from a command number.
pub const fn ioc_dir(cmd: u32) -> u32 {
    (cmd >> IOC_DIRSHIFT) & IOC_DIRMASK
}

/// Extract the type (magic) field from a command number.
pub const fn ioc_type(cmd: u32) -> u8 {
    ((cmd >> IOC_TYPESHIFT) & IOC_TYPEMASK) as u8
}

/// Extract the number (function) field from a command number.
pub const fn ioc_nr(cmd: u32) -> u8 {
    ((cmd >> IOC_NRSHIFT) & IOC_NRMASK) as u8
}

/// Extract the size field from a command number.
pub const fn ioc_size(cmd: u32) -> u32 {
    (cmd >> IOC_SIZESHIFT) & IOC_SIZEMASK
}

// ---------------------------------------------------------------------------
// Well-known ioctl constants
// ---------------------------------------------------------------------------

/// Return the number of bytes available to read on the file descriptor.
pub const FIONREAD: u32 = ioc(IOC_READ, b'f', 127, core::mem::size_of::<i32>());
/// Set or clear non-blocking I/O mode (arg != 0 means non-blocking).
pub const FIONBIO: u32 = ioc(IOC_WRITE, b'f', 126, core::mem::size_of::<i32>());
/// Set close-on-exec flag on the file descriptor.
pub const FIOCLEX: u32 = ioc(IOC_NONE, b'f', 1, 0);
/// Clear close-on-exec flag on the file descriptor.
pub const FIONCLEX: u32 = ioc(IOC_NONE, b'f', 2, 0);

/// Get the terminal window size (`struct winsize`).
pub const TIOCGWINSZ: u32 = ioc(IOC_READ, b'T', 18, core::mem::size_of::<Winsize>());
/// Set the terminal window size (`struct winsize`).
pub const TIOCSWINSZ: u32 = ioc(IOC_WRITE, b'T', 19, core::mem::size_of::<Winsize>());

// ---------------------------------------------------------------------------
// Winsize — terminal window dimensions
// ---------------------------------------------------------------------------

/// Terminal window size (`struct winsize`).
///
/// Used by `TIOCGWINSZ` and `TIOCSWINSZ`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Winsize {
    /// Number of character rows.
    pub ws_row: u16,
    /// Number of character columns.
    pub ws_col: u16,
    /// Width in pixels (often 0 if not known).
    pub ws_xpixel: u16,
    /// Height in pixels (often 0 if not known).
    pub ws_ypixel: u16,
}

impl Winsize {
    /// Construct a `Winsize` with the given dimensions (pixel sizes zeroed).
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
// IoctlCmd — decoded command
// ---------------------------------------------------------------------------

/// Decoded ioctl command fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoctlCmd {
    /// Raw command number.
    pub raw: u32,
    /// Direction (IOC_NONE / IOC_READ / IOC_WRITE / IOC_READ | IOC_WRITE).
    pub dir: u32,
    /// Type (magic) byte.
    pub typ: u8,
    /// Function number within the type.
    pub nr: u8,
    /// Data size in bytes.
    pub size: u32,
}

impl IoctlCmd {
    /// Decode a raw ioctl command number.
    pub const fn decode(cmd: u32) -> Self {
        Self {
            raw: cmd,
            dir: ioc_dir(cmd),
            typ: ioc_type(cmd),
            nr: ioc_nr(cmd),
            size: ioc_size(cmd),
        }
    }

    /// Return `true` if this command transfers data from user to kernel.
    pub const fn is_write(&self) -> bool {
        self.dir & IOC_WRITE != 0
    }

    /// Return `true` if this command transfers data from kernel to user.
    pub const fn is_read(&self) -> bool {
        self.dir & IOC_READ != 0
    }
}

// ---------------------------------------------------------------------------
// IoctlResult — outcome
// ---------------------------------------------------------------------------

/// Result of a successful `ioctl` call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IoctlResult {
    /// Integer return value (semantics depend on the command).
    pub retval: i64,
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
// Command handlers
// ---------------------------------------------------------------------------

/// Handle `FIONREAD` — return bytes available to read.
fn handle_fionread(fd: i32) -> Result<IoctlResult> {
    validate_fd(fd)?;
    // Stub: real implementation queries the underlying file object.
    Ok(IoctlResult { retval: 0 })
}

/// Handle `FIONBIO` — set/clear non-blocking mode.
fn handle_fionbio(fd: i32, arg: u64) -> Result<IoctlResult> {
    validate_fd(fd)?;
    // arg != 0 means enable non-blocking, 0 means disable.
    let _enable = arg != 0;
    // Stub: real implementation updates the file descriptor flags.
    Ok(IoctlResult { retval: 0 })
}

/// Handle `FIOCLEX` — set close-on-exec flag.
fn handle_fioclex(fd: i32) -> Result<IoctlResult> {
    validate_fd(fd)?;
    // Stub: real implementation sets FD_CLOEXEC on the fd.
    Ok(IoctlResult { retval: 0 })
}

/// Handle `FIONCLEX` — clear close-on-exec flag.
fn handle_fionclex(fd: i32) -> Result<IoctlResult> {
    validate_fd(fd)?;
    // Stub: real implementation clears FD_CLOEXEC on the fd.
    Ok(IoctlResult { retval: 0 })
}

/// Handle `TIOCGWINSZ` — get terminal window size.
fn handle_tiocgwinsz(fd: i32) -> Result<(IoctlResult, Winsize)> {
    validate_fd(fd)?;
    // Stub: return a default 80x24 terminal.
    let ws = Winsize::new(24, 80);
    Ok((IoctlResult { retval: 0 }, ws))
}

/// Handle `TIOCSWINSZ` — set terminal window size.
fn handle_tiocswinsz(fd: i32, ws: &Winsize) -> Result<IoctlResult> {
    validate_fd(fd)?;
    // Validate: rows and cols must be non-zero.
    if ws.ws_row == 0 || ws.ws_col == 0 {
        return Err(Error::InvalidArgument);
    }
    // Stub: real implementation updates the tty winsize and sends SIGWINCH.
    Ok(IoctlResult { retval: 0 })
}

// ---------------------------------------------------------------------------
// Public syscall handlers
// ---------------------------------------------------------------------------

/// `ioctl` — control device.
///
/// Dispatches the ioctl `cmd` to the appropriate handler based on the
/// command encoding. Returns the integer result of the operation.
///
/// Supported commands:
/// - `FIONREAD` — bytes available to read
/// - `FIONBIO` — set/clear non-blocking mode
/// - `FIOCLEX` — set close-on-exec
/// - `FIONCLEX` — clear close-on-exec
/// - `TIOCGWINSZ` — get terminal size
/// - `TIOCSWINSZ` — set terminal size
///
/// # Errors
///
/// | `Error`           | Condition                                  |
/// |-------------------|--------------------------------------------|
/// | `InvalidArgument` | `fd < 0` or invalid argument for command   |
/// | `NotSupported`    | Unrecognised command                       |
///
/// Reference: Linux ioctl(2).
pub fn do_ioctl(fd: i32, cmd: u32, arg: u64) -> Result<IoctlResult> {
    validate_fd(fd)?;

    match cmd {
        FIONREAD => handle_fionread(fd),
        FIONBIO => handle_fionbio(fd, arg),
        FIOCLEX => handle_fioclex(fd),
        FIONCLEX => handle_fionclex(fd),
        TIOCGWINSZ => {
            let (result, _ws) = handle_tiocgwinsz(fd)?;
            Ok(result)
        }
        TIOCSWINSZ => {
            // In a real implementation, `arg` would be a user-space pointer
            // to a Winsize struct. Here we use a default for the stub.
            let ws = Winsize::new(24, 80);
            let _ = arg;
            handle_tiocswinsz(fd, &ws)
        }
        _ => Err(Error::InvalidArgument),
    }
}

/// `ioctl` variant that provides `Winsize` data for `TIOCSWINSZ`.
///
/// The syscall layer validates the user-space pointer and copies the
/// `Winsize` before calling this function.
pub fn do_ioctl_tiocswinsz(fd: i32, ws: &Winsize) -> Result<IoctlResult> {
    handle_tiocswinsz(fd, ws)
}

/// `ioctl` variant that returns the window size for `TIOCGWINSZ`.
pub fn do_ioctl_tiocgwinsz(fd: i32) -> Result<Winsize> {
    let (_result, ws) = handle_tiocgwinsz(fd)?;
    Ok(ws)
}

/// Decode the ioctl command number for inspection.
pub fn decode_ioctl_cmd(cmd: u32) -> IoctlCmd {
    IoctlCmd::decode(cmd)
}
