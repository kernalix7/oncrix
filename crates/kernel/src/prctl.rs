// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Process control (`prctl`) implementation.
//!
//! `prctl(2)` allows a process to control various aspects of its own
//! behavior. Each option reads or modifies per-process state stored
//! in [`PrctlState`], which is embedded in the process control block.
//!
//! Supported options:
//! - `PR_SET_NAME` / `PR_GET_NAME`: process/thread name (up to 15 bytes)
//! - `PR_SET_DUMPABLE` / `PR_GET_DUMPABLE`: core dump permission
//! - `PR_SET_KEEPCAPS` / `PR_GET_KEEPCAPS`: keep capabilities on UID change
//! - `PR_SET_NO_NEW_PRIVS` / `PR_GET_NO_NEW_PRIVS`: no-new-privileges flag
//! - `PR_SET_SECCOMP` / `PR_GET_SECCOMP`: seccomp filter mode
//! - `PR_SET_PDEATHSIG` / `PR_GET_PDEATHSIG`: parent-death signal
//!
//! Reference: Linux `kernel/sys.c` (`SYSCALL_DEFINE5(prctl, ...)`).

use oncrix_lib::{Error, Result};

// ── Option constants ──────────────────────────────────────────────

/// Set the parent-death signal.
pub const PR_SET_PDEATHSIG: u64 = 1;
/// Get the parent-death signal.
pub const PR_GET_PDEATHSIG: u64 = 2;
/// Get the dumpable flag.
pub const PR_GET_DUMPABLE: u64 = 3;
/// Set the dumpable flag.
pub const PR_SET_DUMPABLE: u64 = 4;
/// Get the keep-capabilities flag.
pub const PR_GET_KEEPCAPS: u64 = 7;
/// Set the keep-capabilities flag.
pub const PR_SET_KEEPCAPS: u64 = 8;
/// Set the process/thread name.
pub const PR_SET_NAME: u64 = 15;
/// Get the process/thread name.
pub const PR_GET_NAME: u64 = 16;
/// Get the seccomp filter mode.
pub const PR_GET_SECCOMP: u64 = 21;
/// Set the seccomp filter mode.
pub const PR_SET_SECCOMP: u64 = 22;
/// Set the no-new-privileges flag.
pub const PR_SET_NO_NEW_PRIVS: u64 = 38;
/// Get the no-new-privileges flag.
pub const PR_GET_NO_NEW_PRIVS: u64 = 39;

/// Maximum length of a process name (excluding the null terminator).
const PRCTL_NAME_MAX: usize = 15;

/// Total buffer size for the name (15 usable bytes + null terminator).
const PRCTL_NAME_BUF: usize = 16;

// ── Per-process prctl state ───────────────────────────────────────

/// Per-process state controlled via `prctl(2)`.
///
/// This struct is embedded in the process control block (PCB). Each
/// field corresponds to one or more `prctl` options.
#[derive(Debug, Clone)]
pub struct PrctlState {
    /// Process/thread name buffer (null-terminated, up to 15 chars).
    name: [u8; PRCTL_NAME_BUF],
    /// Length of the name in bytes (excluding the null terminator).
    name_len: usize,
    /// Whether the process is dumpable (core dumps permitted).
    dumpable: bool,
    /// Retain capabilities across UID transitions.
    keepcaps: bool,
    /// No-new-privileges flag (one-way: once set, cannot be cleared).
    no_new_privs: bool,
    /// Seccomp filter mode (0 = disabled, 1 = strict, 2 = filter).
    seccomp_mode: u32,
    /// Signal sent to this process when its parent dies (0 = none).
    pdeathsig: u32,
}

impl Default for PrctlState {
    fn default() -> Self {
        Self::new()
    }
}

impl PrctlState {
    /// Create a new `PrctlState` with sensible defaults.
    ///
    /// - `dumpable` = `true` (matches Linux default for non-suid)
    /// - all other flags are `false` / `0`
    pub const fn new() -> Self {
        Self {
            name: [0u8; PRCTL_NAME_BUF],
            name_len: 0,
            dumpable: true,
            keepcaps: false,
            no_new_privs: false,
            seccomp_mode: 0,
            pdeathsig: 0,
        }
    }

    // ── Name ──────────────────────────────────────────────────────

    /// Set the process/thread name.
    ///
    /// Copies up to [`PRCTL_NAME_MAX`] (15) bytes from `name` and
    /// appends a null terminator. If `name` is longer than 15 bytes
    /// it is silently truncated (matching Linux behavior).
    pub fn set_name(&mut self, name: &[u8]) -> Result<()> {
        let len = if name.len() > PRCTL_NAME_MAX {
            PRCTL_NAME_MAX
        } else {
            name.len()
        };
        self.name = [0u8; PRCTL_NAME_BUF];
        let dst = &mut self.name[..len];
        dst.copy_from_slice(&name[..len]);
        // Null terminator is already guaranteed by the zero-init above.
        self.name_len = len;
        Ok(())
    }

    /// Copy the process/thread name into `buf`.
    ///
    /// Returns the number of bytes written (excluding the null
    /// terminator). The output is always null-terminated if `buf`
    /// has space for at least `name_len + 1` bytes.
    pub fn get_name(&self, buf: &mut [u8]) -> usize {
        let copy_len = if self.name_len < buf.len() {
            self.name_len
        } else {
            buf.len().saturating_sub(1)
        };
        buf[..copy_len].copy_from_slice(&self.name[..copy_len]);
        // Null-terminate if there is room.
        if copy_len < buf.len() {
            buf[copy_len] = 0;
        }
        copy_len
    }

    // ── Dumpable ──────────────────────────────────────────────────

    /// Set the dumpable flag.
    ///
    /// Only values `0` (not dumpable) and `1` (dumpable) are accepted.
    /// Returns `InvalidArgument` for any other value.
    pub fn set_dumpable(&mut self, val: u32) -> Result<()> {
        match val {
            0 => {
                self.dumpable = false;
                Ok(())
            }
            1 => {
                self.dumpable = true;
                Ok(())
            }
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Get the dumpable flag as a `u32` (0 or 1).
    pub fn get_dumpable(&self) -> u32 {
        u32::from(self.dumpable)
    }

    // ── Keep capabilities ─────────────────────────────────────────

    /// Set the keep-capabilities flag.
    ///
    /// Only values `0` and `1` are accepted.
    pub fn set_keepcaps(&mut self, val: u32) -> Result<()> {
        match val {
            0 => {
                self.keepcaps = false;
                Ok(())
            }
            1 => {
                self.keepcaps = true;
                Ok(())
            }
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Get the keep-capabilities flag as a `u32` (0 or 1).
    pub fn get_keepcaps(&self) -> u32 {
        u32::from(self.keepcaps)
    }

    // ── No-new-privileges ─────────────────────────────────────────

    /// Set the no-new-privileges flag.
    ///
    /// This is a **one-way** operation: once set to `1` it can never
    /// be cleared. Passing `0` (or any value other than `1`) returns
    /// `InvalidArgument`.
    pub fn set_no_new_privs(&mut self, val: u32) -> Result<()> {
        if val != 1 {
            return Err(Error::InvalidArgument);
        }
        self.no_new_privs = true;
        Ok(())
    }

    /// Get the no-new-privileges flag as a `u32` (0 or 1).
    pub fn get_no_new_privs(&self) -> u32 {
        u32::from(self.no_new_privs)
    }

    // ── Seccomp ───────────────────────────────────────────────────

    /// Set the seccomp filter mode.
    ///
    /// Valid modes: `0` (disabled), `1` (strict), `2` (filter).
    /// Transitioning from a higher mode to a lower one (e.g., from
    /// filter back to disabled) is forbidden and returns
    /// `InvalidArgument`.
    pub fn set_seccomp(&mut self, mode: u32) -> Result<()> {
        if mode > 2 {
            return Err(Error::InvalidArgument);
        }
        // Seccomp mode can only be tightened, never loosened.
        if mode < self.seccomp_mode {
            return Err(Error::InvalidArgument);
        }
        self.seccomp_mode = mode;
        Ok(())
    }

    /// Get the current seccomp filter mode.
    pub fn get_seccomp(&self) -> u32 {
        self.seccomp_mode
    }

    // ── Parent-death signal ───────────────────────────────────────

    /// Set the parent-death signal.
    ///
    /// `sig` must be a valid signal number (1..=64) or `0` to clear.
    /// Returns `InvalidArgument` for out-of-range values.
    pub fn set_pdeathsig(&mut self, sig: u32) -> Result<()> {
        if sig > 64 {
            return Err(Error::InvalidArgument);
        }
        self.pdeathsig = sig;
        Ok(())
    }

    /// Get the parent-death signal (0 = none).
    pub fn get_pdeathsig(&self) -> u32 {
        self.pdeathsig
    }
}

// ── Main dispatch ─────────────────────────────────────────────────

/// Dispatch a `prctl(2)` call.
///
/// Arguments:
/// - `state`: mutable reference to the calling process's prctl state
/// - `option`: the prctl option constant (e.g., `PR_SET_NAME`)
/// - `arg2`: option-specific argument
///
/// Returns the result value on success, or an error. For `PR_SET_*`
/// operations the return value is `0`; for `PR_GET_*` operations it
/// is the requested value.
pub fn do_prctl(state: &mut PrctlState, option: u64, arg2: u64) -> Result<u64> {
    match option {
        PR_SET_PDEATHSIG => {
            state.set_pdeathsig(arg2 as u32)?;
            Ok(0)
        }
        PR_GET_PDEATHSIG => {
            // In the real implementation, the value would be written
            // to the user-space pointer in arg2 via copy_to_user.
            // Here we return it directly for the kernel-side API.
            Ok(u64::from(state.get_pdeathsig()))
        }
        PR_GET_DUMPABLE => Ok(u64::from(state.get_dumpable())),
        PR_SET_DUMPABLE => {
            state.set_dumpable(arg2 as u32)?;
            Ok(0)
        }
        PR_GET_KEEPCAPS => Ok(u64::from(state.get_keepcaps())),
        PR_SET_KEEPCAPS => {
            state.set_keepcaps(arg2 as u32)?;
            Ok(0)
        }
        PR_SET_NAME => {
            // In the real implementation, `arg2` is a user pointer
            // to a null-terminated string. The kernel would
            // copy_from_user up to 16 bytes. Here we treat it as
            // a stub and set an empty name.
            // Stub: would copy_from_user(arg2, &mut buf, 16).
            let _ = arg2;
            state.set_name(&[])?;
            Ok(0)
        }
        PR_GET_NAME => {
            // In the real implementation, `arg2` is a user pointer
            // where the kernel writes the 16-byte name buffer via
            // copy_to_user. Stub: the caller must handle copy_to_user.
            let _ = arg2;
            Ok(0)
        }
        PR_GET_SECCOMP => Ok(u64::from(state.get_seccomp())),
        PR_SET_SECCOMP => {
            state.set_seccomp(arg2 as u32)?;
            Ok(0)
        }
        PR_SET_NO_NEW_PRIVS => {
            state.set_no_new_privs(arg2 as u32)?;
            Ok(0)
        }
        PR_GET_NO_NEW_PRIVS => Ok(u64::from(state.get_no_new_privs())),
        _ => Err(Error::InvalidArgument),
    }
}
