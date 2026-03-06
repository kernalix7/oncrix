// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `fsconfig(2)` syscall handler — configure a filesystem context.
//!
//! `fsconfig` is used to pass parameters and trigger commands on a filesystem
//! context created with `fsopen(2)`.  It is part of the new mount API
//! introduced in Linux 5.2.
//!
//! # Linux reference
//!
//! Linux-specific: `fsconfig(2)` man page.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Command constants
// ---------------------------------------------------------------------------

/// Set a configuration key to a NUL-terminated string value.
pub const FSCONFIG_SET_FLAG: u32 = 0;
/// Set a configuration key to a NUL-terminated string value.
pub const FSCONFIG_SET_STRING: u32 = 1;
/// Set a configuration key to a binary blob.
pub const FSCONFIG_SET_BINARY: u32 = 2;
/// Set a configuration key to an integer value.
pub const FSCONFIG_SET_PATH: u32 = 3;
/// Set a path with file descriptor.
pub const FSCONFIG_SET_PATH_EMPTY: u32 = 4;
/// Set configuration with fd.
pub const FSCONFIG_SET_FD: u32 = 5;
/// Create the filesystem.
pub const FSCONFIG_CMD_CREATE: u32 = 6;
/// Reconfigure an existing filesystem.
pub const FSCONFIG_CMD_RECONFIGURE: u32 = 7;
/// Create an anonymous filesystem context.
pub const FSCONFIG_CMD_CREATE_EXCL: u32 = 8;

/// Maximum valid command.
const MAX_CMD: u32 = FSCONFIG_CMD_CREATE_EXCL;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The parsed `fsconfig` command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsconfigCmd {
    /// Boolean flag parameter.
    SetFlag,
    /// String parameter.
    SetString,
    /// Binary blob parameter.
    SetBinary,
    /// Path parameter (may require `fd`).
    SetPath,
    /// Path parameter with empty pathname (use `fd`).
    SetPathEmpty,
    /// File descriptor parameter.
    SetFd,
    /// Create the filesystem object.
    CmdCreate,
    /// Reconfigure the filesystem.
    CmdReconfigure,
    /// Create an exclusive filesystem context.
    CmdCreateExcl,
}

impl FsconfigCmd {
    /// Parse from a raw integer.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` for unknown commands.
    pub fn from_raw(cmd: u32) -> Result<Self> {
        match cmd {
            FSCONFIG_SET_FLAG => Ok(Self::SetFlag),
            FSCONFIG_SET_STRING => Ok(Self::SetString),
            FSCONFIG_SET_BINARY => Ok(Self::SetBinary),
            FSCONFIG_SET_PATH => Ok(Self::SetPath),
            FSCONFIG_SET_PATH_EMPTY => Ok(Self::SetPathEmpty),
            FSCONFIG_SET_FD => Ok(Self::SetFd),
            FSCONFIG_CMD_CREATE => Ok(Self::CmdCreate),
            FSCONFIG_CMD_RECONFIGURE => Ok(Self::CmdReconfigure),
            FSCONFIG_CMD_CREATE_EXCL => Ok(Self::CmdCreateExcl),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Return `true` if this is a "set parameter" command (not a lifecycle command).
    pub fn is_set_cmd(&self) -> bool {
        matches!(
            self,
            Self::SetFlag
                | Self::SetString
                | Self::SetBinary
                | Self::SetPath
                | Self::SetPathEmpty
                | Self::SetFd
        )
    }

    /// Return `true` if this is a lifecycle command.
    pub fn is_lifecycle_cmd(&self) -> bool {
        matches!(
            self,
            Self::CmdCreate | Self::CmdReconfigure | Self::CmdCreateExcl
        )
    }
}

/// Validated `fsconfig` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsconfigRequest {
    /// Filesystem context fd.
    pub fs_fd: i32,
    /// Parsed command.
    pub cmd: FsconfigCmd,
    /// User-space pointer to the key string.
    pub key: usize,
    /// User-space pointer to the value (may be 0 for flag/lifecycle commands).
    pub value: usize,
    /// Auxiliary integer (used for `SET_FD` and `SET_PATH`).
    pub aux: i32,
}

impl FsconfigRequest {
    /// Construct a new request.
    pub const fn new(fs_fd: i32, cmd: FsconfigCmd, key: usize, value: usize, aux: i32) -> Self {
        Self {
            fs_fd,
            cmd,
            key,
            value,
            aux,
        }
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `fsconfig(2)`.
///
/// Validates all arguments and returns a structured request.
///
/// # Arguments
///
/// - `fs_fd` — filesystem context fd (from `fsopen`)
/// - `cmd`   — command to execute
/// - `key`   — user-space pointer to parameter key (may be 0 for lifecycle cmds)
/// - `value` — user-space pointer to parameter value
/// - `aux`   — auxiliary integer (fd or flag)
///
/// # Errors
///
/// | `Error`           | Condition                                        |
/// |-------------------|--------------------------------------------------|
/// | `InvalidArgument` | Unknown command, negative fs_fd, null key for set |
/// | `NotFound`        | `fs_fd` is not a filesystem context              |
pub fn do_fsconfig(
    fs_fd: i32,
    cmd: u32,
    key: usize,
    value: usize,
    aux: i32,
) -> Result<FsconfigRequest> {
    if fs_fd < 0 {
        return Err(Error::InvalidArgument);
    }
    if cmd > MAX_CMD {
        return Err(Error::InvalidArgument);
    }
    let parsed_cmd = FsconfigCmd::from_raw(cmd)?;
    // Set commands require a non-null key.
    if parsed_cmd.is_set_cmd() && key == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(FsconfigRequest::new(fs_fd, parsed_cmd, key, value, aux))
}

/// Return `true` if the command requires the context to be in the config phase.
pub fn requires_config_phase(cmd: &FsconfigCmd) -> bool {
    cmd.is_set_cmd() || matches!(cmd, FsconfigCmd::CmdCreate | FsconfigCmd::CmdCreateExcl)
}

/// Return `true` if the command requires the context to be in the created phase.
pub fn requires_created_phase(cmd: &FsconfigCmd) -> bool {
    matches!(cmd, FsconfigCmd::CmdReconfigure)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_string_ok() {
        let req = do_fsconfig(3, FSCONFIG_SET_STRING, 0x1000, 0x2000, 0).unwrap();
        assert_eq!(req.cmd, FsconfigCmd::SetString);
        assert!(req.cmd.is_set_cmd());
    }

    #[test]
    fn cmd_create_ok() {
        let req = do_fsconfig(3, FSCONFIG_CMD_CREATE, 0, 0, 0).unwrap();
        assert_eq!(req.cmd, FsconfigCmd::CmdCreate);
        assert!(req.cmd.is_lifecycle_cmd());
    }

    #[test]
    fn negative_fd_rejected() {
        assert_eq!(
            do_fsconfig(-1, FSCONFIG_SET_FLAG, 0x1000, 0, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn null_key_for_set_rejected() {
        assert_eq!(
            do_fsconfig(3, FSCONFIG_SET_STRING, 0, 0x2000, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unknown_cmd_rejected() {
        assert_eq!(
            do_fsconfig(3, 0xFF, 0x1000, 0, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn lifecycle_cmd_no_key_ok() {
        // Lifecycle commands do not require a key.
        let req = do_fsconfig(3, FSCONFIG_CMD_RECONFIGURE, 0, 0, 0).unwrap();
        assert!(req.cmd.is_lifecycle_cmd());
        assert!(requires_created_phase(&req.cmd));
    }

    #[test]
    fn requires_config_phase_check() {
        let cmd = FsconfigCmd::SetString;
        assert!(requires_config_phase(&cmd));
        let cmd2 = FsconfigCmd::CmdReconfigure;
        assert!(!requires_config_phase(&cmd2));
    }
}
