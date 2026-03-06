// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Generic VFS ioctl dispatch layer.
//!
//! Provides a unified ioctl dispatch mechanism for VFS objects,
//! routing ioctl commands to filesystem-specific handlers or
//! implementing common generic ioctls at the VFS level.

use oncrix_lib::{Error, Result};

/// Maximum size of ioctl argument buffer (64 bytes).
pub const IOCTL_ARG_MAX: usize = 64;

/// ioctl command encoding: direction, size, type, number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoctlCmd(pub u32);

impl IoctlCmd {
    /// ioctl direction: none (no data transfer).
    pub const DIR_NONE: u32 = 0;
    /// ioctl direction: write (user → kernel).
    pub const DIR_WRITE: u32 = 1;
    /// ioctl direction: read (kernel → user).
    pub const DIR_READ: u32 = 2;
    /// ioctl direction: read+write.
    pub const DIR_RW: u32 = 3;

    /// Create an ioctl command value from components.
    pub const fn new(dir: u32, size: u32, kind: u8, nr: u8) -> Self {
        IoctlCmd((dir << 30) | (size << 16) | ((kind as u32) << 8) | (nr as u32))
    }

    /// Extract direction field.
    pub fn direction(self) -> u32 {
        (self.0 >> 30) & 0x3
    }

    /// Extract argument size field.
    pub fn size(self) -> u32 {
        (self.0 >> 16) & 0x3FFF
    }

    /// Extract type (magic) field.
    pub fn kind(self) -> u8 {
        ((self.0 >> 8) & 0xFF) as u8
    }

    /// Extract command number field.
    pub fn nr(self) -> u8 {
        (self.0 & 0xFF) as u8
    }
}

/// Common VFS-level ioctl commands.
pub mod cmds {
    use super::IoctlCmd;
    /// Query filesystem type magic number.
    pub const FIOCLEX: IoctlCmd = IoctlCmd(0x5451);
    /// Clear FD close-on-exec flag.
    pub const FIONCLEX: IoctlCmd = IoctlCmd(0x5450);
    /// Get number of bytes available to read.
    pub const FIONREAD: IoctlCmd = IoctlCmd(0x541B);
    /// Set non-blocking I/O mode.
    pub const FIONBIO: IoctlCmd = IoctlCmd(0x5421);
    /// Set async I/O mode.
    pub const FIOASYNC: IoctlCmd = IoctlCmd(0x5452);
    /// Get file size in blocks.
    pub const FIGETBSZ: IoctlCmd = IoctlCmd(0x1272);
}

/// Result of ioctl dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoctlResult {
    /// ioctl was handled; contains return value.
    Handled(i64),
    /// ioctl not recognized; try next handler.
    NotHandled,
}

/// Context provided to ioctl handlers.
#[derive(Debug)]
pub struct IoctlContext {
    /// The ioctl command.
    pub cmd: IoctlCmd,
    /// Pointer to user-space argument (or inline value for small args).
    pub arg: usize,
    /// File flags at the time of the call.
    pub file_flags: u32,
}

impl IoctlContext {
    /// Create a new ioctl context.
    pub fn new(cmd: u32, arg: usize, file_flags: u32) -> Self {
        IoctlContext {
            cmd: IoctlCmd(cmd),
            arg,
            file_flags,
        }
    }
}

/// Trait for objects that can handle ioctls.
pub trait IoctlHandler {
    /// Dispatch an ioctl command.
    ///
    /// Returns `IoctlResult::Handled(v)` if the command was handled,
    /// or `IoctlResult::NotHandled` to pass to the next handler.
    fn ioctl(&self, ctx: &IoctlContext) -> Result<IoctlResult>;
}

/// VFS ioctl dispatcher: chains multiple handlers.
pub struct IoctlDispatcher {
    /// Number of registered handlers.
    count: usize,
    /// Handler function pointers (up to 8 handlers).
    handlers: [Option<fn(&IoctlContext) -> Result<IoctlResult>>; 8],
}

impl IoctlDispatcher {
    /// Create a new empty dispatcher.
    pub const fn new() -> Self {
        IoctlDispatcher {
            count: 0,
            handlers: [None; 8],
        }
    }

    /// Register a handler function.
    pub fn register(&mut self, f: fn(&IoctlContext) -> Result<IoctlResult>) -> Result<()> {
        if self.count >= 8 {
            return Err(Error::OutOfMemory);
        }
        self.handlers[self.count] = Some(f);
        self.count += 1;
        Ok(())
    }

    /// Dispatch an ioctl through registered handlers in order.
    pub fn dispatch(&self, ctx: &IoctlContext) -> Result<i64> {
        for i in 0..self.count {
            if let Some(handler) = self.handlers[i] {
                match handler(ctx)? {
                    IoctlResult::Handled(v) => return Ok(v),
                    IoctlResult::NotHandled => continue,
                }
            }
        }
        Err(Error::NotImplemented)
    }
}

impl Default for IoctlDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Generic VFS ioctl handler for common commands.
///
/// Handles ioctls that apply to all file types regardless of filesystem.
pub fn vfs_generic_ioctl(ctx: &IoctlContext) -> Result<IoctlResult> {
    match ctx.cmd.0 {
        0x5451 => {
            // FIOCLEX: set close-on-exec — handled by fd layer
            Ok(IoctlResult::Handled(0))
        }
        0x5450 => {
            // FIONCLEX: clear close-on-exec — handled by fd layer
            Ok(IoctlResult::Handled(0))
        }
        0x5452 => {
            // FIOASYNC: async I/O flag — update file flags
            Ok(IoctlResult::Handled(0))
        }
        _ => Ok(IoctlResult::NotHandled),
    }
}

/// Validate an ioctl command for a given file type.
///
/// Returns `Ok(())` if the command is permitted, `Err(InvalidArgument)` otherwise.
pub fn validate_ioctl_cmd(cmd: IoctlCmd, is_regular_file: bool) -> Result<()> {
    // Block device-specific ioctls must not be sent to regular files.
    if is_regular_file && cmd.kind() == b'B' {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Build a standard ioctl command from type, number, and size.
pub const fn _ior(kind: u8, nr: u8, size: u32) -> IoctlCmd {
    IoctlCmd::new(IoctlCmd::DIR_READ, size, kind, nr)
}

/// Build a write ioctl command.
pub const fn _iow(kind: u8, nr: u8, size: u32) -> IoctlCmd {
    IoctlCmd::new(IoctlCmd::DIR_WRITE, size, kind, nr)
}

/// Build a read+write ioctl command.
pub const fn _iowr(kind: u8, nr: u8, size: u32) -> IoctlCmd {
    IoctlCmd::new(IoctlCmd::DIR_RW, size, kind, nr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioctl_cmd_fields() {
        let cmd = IoctlCmd::new(IoctlCmd::DIR_READ, 4, b'f', 1);
        assert_eq!(cmd.direction(), IoctlCmd::DIR_READ);
        assert_eq!(cmd.size(), 4);
        assert_eq!(cmd.kind(), b'f');
        assert_eq!(cmd.nr(), 1);
    }
}
