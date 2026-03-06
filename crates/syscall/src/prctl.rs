// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `prctl(2)` syscall handler — process control operations.
//!
//! Provides a per-PID table of [`PrctlState`] entries and a top-level
//! dispatcher ([`do_prctl`]) that fans out to the appropriate getter
//! or setter based on the requested option.
//!
//! Supported options:
//! - `PR_SET_NAME` / `PR_GET_NAME` — process/thread name (up to 15 bytes)
//! - `PR_SET_DUMPABLE` / `PR_GET_DUMPABLE` — core dump permission
//! - `PR_SET_SECCOMP` / `PR_GET_SECCOMP` — seccomp filter mode
//! - `PR_SET_NO_NEW_PRIVS` / `PR_GET_NO_NEW_PRIVS` — one-way privilege flag
//! - `PR_SET_TIMER_SLACK` / `PR_GET_TIMER_SLACK` — timer slack value
//! - `PR_SET_CHILD_SUBREAPER` / `PR_GET_CHILD_SUBREAPER` — child subreaper
//! - `PR_SET_PDEATHSIG` / `PR_GET_PDEATHSIG` — parent-death signal
//! - `PR_CAP_BSET_READ` / `PR_CAP_BSET_DROP` — capability bounding set
//! - `PR_SET_KEEPCAPS` / `PR_GET_KEEPCAPS` — keep capabilities on UID change

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Option constants (Linux-compatible values, typed as i32)
// ---------------------------------------------------------------------------

/// Set the parent-death signal.
pub const PR_SET_PDEATHSIG: i32 = 1;
/// Get the parent-death signal.
pub const PR_GET_PDEATHSIG: i32 = 2;
/// Get the dumpable flag.
pub const PR_GET_DUMPABLE: i32 = 3;
/// Set the dumpable flag.
pub const PR_SET_DUMPABLE: i32 = 4;
/// Get the keep-capabilities flag.
pub const PR_GET_KEEPCAPS: i32 = 7;
/// Set the keep-capabilities flag.
pub const PR_SET_KEEPCAPS: i32 = 8;
/// Set the process/thread name.
pub const PR_SET_NAME: i32 = 15;
/// Get the process/thread name.
pub const PR_GET_NAME: i32 = 16;
/// Get the seccomp filter mode.
pub const PR_GET_SECCOMP: i32 = 21;
/// Set the seccomp filter mode.
pub const PR_SET_SECCOMP: i32 = 22;
/// Read a capability from the bounding set.
pub const PR_CAP_BSET_READ: i32 = 23;
/// Drop a capability from the bounding set.
pub const PR_CAP_BSET_DROP: i32 = 24;
/// Set the timer slack value (nanoseconds).
pub const PR_SET_TIMER_SLACK: i32 = 29;
/// Get the timer slack value (nanoseconds).
pub const PR_GET_TIMER_SLACK: i32 = 30;
/// Set the no-new-privileges flag.
pub const PR_SET_NO_NEW_PRIVS: i32 = 38;
/// Get the no-new-privileges flag.
pub const PR_GET_NO_NEW_PRIVS: i32 = 39;
/// Set the child-subreaper flag.
pub const PR_SET_CHILD_SUBREAPER: i32 = 36;
/// Get the child-subreaper flag.
pub const PR_GET_CHILD_SUBREAPER: i32 = 37;

/// Maximum length of a process name (excluding null terminator).
const PRCTL_NAME_MAX: usize = 15;

/// Total name buffer size (15 usable bytes + null terminator).
const PRCTL_NAME_BUF: usize = 16;

/// Maximum PID table entries.
const MAX_PRCTL_ENTRIES: usize = 256;

/// Default timer slack (50 microseconds in nanoseconds, matches Linux).
const DEFAULT_TIMER_SLACK_NS: u64 = 50_000;

/// Maximum number of Linux capabilities (CAP_LAST_CAP + 1).
const CAP_LAST_CAP: u64 = 40;

// ---------------------------------------------------------------------------
// PrctlOption enum
// ---------------------------------------------------------------------------

/// Typed representation of a `prctl` option constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PrctlOption {
    /// Set the process/thread name.
    SetName,
    /// Get the process/thread name.
    #[default]
    GetName,
    /// Set the dumpable flag.
    SetDumpable,
    /// Get the dumpable flag.
    GetDumpable,
    /// Set the seccomp filter mode.
    SetSeccomp,
    /// Get the seccomp filter mode.
    GetSeccomp,
    /// Set the no-new-privileges flag.
    SetNoNewPrivs,
    /// Get the no-new-privileges flag.
    GetNoNewPrivs,
    /// Set the timer slack value.
    SetTimerSlack,
    /// Get the timer slack value.
    GetTimerSlack,
    /// Set the child-subreaper flag.
    SetChildSubreaper,
    /// Get the child-subreaper flag.
    GetChildSubreaper,
    /// Set the parent-death signal.
    SetPdeathsig,
    /// Get the parent-death signal.
    GetPdeathsig,
    /// Read a capability from the bounding set.
    CapBsetRead,
    /// Drop a capability from the bounding set.
    CapBsetDrop,
    /// Set the keep-capabilities flag.
    SetKeepCaps,
    /// Get the keep-capabilities flag.
    GetKeepCaps,
}

impl PrctlOption {
    /// Convert a raw `i32` option value to a typed [`PrctlOption`].
    ///
    /// Returns `InvalidArgument` for unrecognised option codes.
    pub fn from_i32(op: i32) -> Result<Self> {
        match op {
            PR_SET_NAME => Ok(Self::SetName),
            PR_GET_NAME => Ok(Self::GetName),
            PR_SET_DUMPABLE => Ok(Self::SetDumpable),
            PR_GET_DUMPABLE => Ok(Self::GetDumpable),
            PR_SET_SECCOMP => Ok(Self::SetSeccomp),
            PR_GET_SECCOMP => Ok(Self::GetSeccomp),
            PR_SET_NO_NEW_PRIVS => Ok(Self::SetNoNewPrivs),
            PR_GET_NO_NEW_PRIVS => Ok(Self::GetNoNewPrivs),
            PR_SET_TIMER_SLACK => Ok(Self::SetTimerSlack),
            PR_GET_TIMER_SLACK => Ok(Self::GetTimerSlack),
            PR_SET_CHILD_SUBREAPER => Ok(Self::SetChildSubreaper),
            PR_GET_CHILD_SUBREAPER => Ok(Self::GetChildSubreaper),
            PR_SET_PDEATHSIG => Ok(Self::SetPdeathsig),
            PR_GET_PDEATHSIG => Ok(Self::GetPdeathsig),
            PR_CAP_BSET_READ => Ok(Self::CapBsetRead),
            PR_CAP_BSET_DROP => Ok(Self::CapBsetDrop),
            PR_SET_KEEPCAPS => Ok(Self::SetKeepCaps),
            PR_GET_KEEPCAPS => Ok(Self::GetKeepCaps),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ---------------------------------------------------------------------------
// Per-process prctl state
// ---------------------------------------------------------------------------

/// Per-process state controlled via `prctl(2)`.
///
/// Each field corresponds to one or more `prctl` options. A default
/// instance mirrors typical Linux defaults for a non-setuid process.
#[derive(Debug, Clone)]
pub struct PrctlState {
    /// Process/thread name buffer (null-terminated, up to 15 chars).
    name: [u8; PRCTL_NAME_BUF],
    /// Length of the name (excluding null terminator).
    name_len: usize,
    /// Whether the process is dumpable (core dumps permitted).
    dumpable: bool,
    /// No-new-privileges flag (one-way: cannot be cleared once set).
    no_new_privs: bool,
    /// Retain capabilities across UID transitions.
    keep_caps: bool,
    /// Act as subreaper for orphaned descendant processes.
    child_subreaper: bool,
    /// Timer slack value in nanoseconds.
    timer_slack_ns: u64,
    /// Signal sent to this process when its parent dies (0 = none).
    pdeathsig: i32,
    /// Seccomp filter mode (0 = disabled, 1 = strict, 2 = filter).
    seccomp_mode: u32,
}

impl Default for PrctlState {
    fn default() -> Self {
        Self {
            name: [0u8; PRCTL_NAME_BUF],
            name_len: 0,
            dumpable: true,
            no_new_privs: false,
            keep_caps: false,
            child_subreaper: false,
            timer_slack_ns: DEFAULT_TIMER_SLACK_NS,
            pdeathsig: 0,
            seccomp_mode: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// PrctlTable — per-PID indexed table
// ---------------------------------------------------------------------------

/// Table of per-process [`PrctlState`] entries, indexed by PID slot.
///
/// Supports up to [`MAX_PRCTL_ENTRIES`] (256) concurrent processes.
pub struct PrctlTable {
    /// Fixed array of prctl state entries, one per PID slot.
    entries: [PrctlState; MAX_PRCTL_ENTRIES],
    /// Number of initialised entries.
    count: usize,
}

impl Default for PrctlTable {
    fn default() -> Self {
        // Build the array without requiring Copy on PrctlState.
        let entries = core::array::from_fn(|_| PrctlState::default());
        Self { entries, count: 0 }
    }
}

impl PrctlTable {
    /// Validate that `pid_idx` is within bounds.
    fn validate_idx(&self, pid_idx: usize) -> Result<()> {
        if pid_idx >= MAX_PRCTL_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Initialise the prctl state for a new process at `pid_idx`.
    ///
    /// Resets the slot to default values and increments the count.
    pub fn init_for_pid(&mut self, pid_idx: usize) -> Result<()> {
        self.validate_idx(pid_idx)?;
        self.entries[pid_idx] = PrctlState::default();
        self.count = self.count.saturating_add(1);
        Ok(())
    }

    // ── Name ──────────────────────────────────────────────────────

    /// Set the process/thread name for `pid_idx`.
    ///
    /// Copies up to [`PRCTL_NAME_MAX`] bytes from `name`; longer
    /// inputs are silently truncated (matching Linux behavior).
    pub fn set_name(&mut self, pid_idx: usize, name: &[u8]) -> Result<()> {
        self.validate_idx(pid_idx)?;
        let entry = &mut self.entries[pid_idx];
        let len = name.len().min(PRCTL_NAME_MAX);
        entry.name = [0u8; PRCTL_NAME_BUF];
        entry.name[..len].copy_from_slice(&name[..len]);
        entry.name_len = len;
        Ok(())
    }

    /// Get the process/thread name for `pid_idx`.
    ///
    /// Returns a slice of the name bytes (excluding the null
    /// terminator).
    pub fn get_name(&self, pid_idx: usize) -> Result<&[u8]> {
        self.validate_idx(pid_idx)?;
        let entry = &self.entries[pid_idx];
        Ok(&entry.name[..entry.name_len])
    }

    // ── Dumpable ──────────────────────────────────────────────────

    /// Set the dumpable flag for `pid_idx`.
    ///
    /// Only `0` (not dumpable) and `1` (dumpable) are accepted.
    pub fn set_dumpable(&mut self, pid_idx: usize, val: bool) -> Result<()> {
        self.validate_idx(pid_idx)?;
        self.entries[pid_idx].dumpable = val;
        Ok(())
    }

    /// Get the dumpable flag for `pid_idx`.
    pub fn get_dumpable(&self, pid_idx: usize) -> Result<bool> {
        self.validate_idx(pid_idx)?;
        Ok(self.entries[pid_idx].dumpable)
    }

    // ── No-new-privileges ─────────────────────────────────────────

    /// Set the no-new-privileges flag for `pid_idx`.
    ///
    /// This is a **one-way** operation: once set it cannot be cleared.
    pub fn set_no_new_privs(&mut self, pid_idx: usize) -> Result<()> {
        self.validate_idx(pid_idx)?;
        self.entries[pid_idx].no_new_privs = true;
        Ok(())
    }

    /// Get the no-new-privileges flag for `pid_idx`.
    pub fn get_no_new_privs(&self, pid_idx: usize) -> Result<bool> {
        self.validate_idx(pid_idx)?;
        Ok(self.entries[pid_idx].no_new_privs)
    }

    // ── Timer slack ───────────────────────────────────────────────

    /// Set the timer slack value (nanoseconds) for `pid_idx`.
    ///
    /// A value of `0` resets to the default slack.
    pub fn set_timer_slack(&mut self, pid_idx: usize, ns: u64) -> Result<()> {
        self.validate_idx(pid_idx)?;
        self.entries[pid_idx].timer_slack_ns = if ns == 0 { DEFAULT_TIMER_SLACK_NS } else { ns };
        Ok(())
    }

    /// Get the timer slack value (nanoseconds) for `pid_idx`.
    pub fn get_timer_slack(&self, pid_idx: usize) -> Result<u64> {
        self.validate_idx(pid_idx)?;
        Ok(self.entries[pid_idx].timer_slack_ns)
    }

    // ── Child subreaper ───────────────────────────────────────────

    /// Set the child-subreaper flag for `pid_idx`.
    pub fn set_child_subreaper(&mut self, pid_idx: usize, val: bool) -> Result<()> {
        self.validate_idx(pid_idx)?;
        self.entries[pid_idx].child_subreaper = val;
        Ok(())
    }

    /// Get the child-subreaper flag for `pid_idx`.
    pub fn get_child_subreaper(&self, pid_idx: usize) -> Result<bool> {
        self.validate_idx(pid_idx)?;
        Ok(self.entries[pid_idx].child_subreaper)
    }

    // ── Parent-death signal ───────────────────────────────────────

    /// Set the parent-death signal for `pid_idx`.
    ///
    /// `sig` must be in `0..=64` (0 clears the signal).
    pub fn set_pdeathsig(&mut self, pid_idx: usize, sig: i32) -> Result<()> {
        self.validate_idx(pid_idx)?;
        if !(0..=64).contains(&sig) {
            return Err(Error::InvalidArgument);
        }
        self.entries[pid_idx].pdeathsig = sig;
        Ok(())
    }

    /// Get the parent-death signal for `pid_idx`.
    pub fn get_pdeathsig(&self, pid_idx: usize) -> Result<i32> {
        self.validate_idx(pid_idx)?;
        Ok(self.entries[pid_idx].pdeathsig)
    }

    // ── Keep capabilities ─────────────────────────────────────────

    /// Set the keep-capabilities flag for `pid_idx`.
    pub fn set_keepcaps(&mut self, pid_idx: usize, val: bool) -> Result<()> {
        self.validate_idx(pid_idx)?;
        self.entries[pid_idx].keep_caps = val;
        Ok(())
    }

    /// Get the keep-capabilities flag for `pid_idx`.
    pub fn get_keepcaps(&self, pid_idx: usize) -> Result<bool> {
        self.validate_idx(pid_idx)?;
        Ok(self.entries[pid_idx].keep_caps)
    }
}

// ---------------------------------------------------------------------------
// Syscall dispatcher
// ---------------------------------------------------------------------------

/// Top-level `prctl(2)` syscall handler.
///
/// Dispatches to the appropriate getter or setter in `table` based on
/// `option`. Arguments `arg2`–`arg5` are option-specific; unused
/// arguments are silently ignored.
///
/// # Returns
///
/// - `PR_SET_*` operations return `0` on success.
/// - `PR_GET_*` operations return the requested value as `u64`.
/// - Unknown or invalid options return `Error::InvalidArgument`.
pub fn do_prctl(
    table: &mut PrctlTable,
    option: i32,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    pid_idx: usize,
) -> Result<u64> {
    let opt = PrctlOption::from_i32(option)?;

    // Suppress unused-variable warnings for currently-unused args.
    let _ = (arg3, arg4, arg5);

    match opt {
        // ── Name ──────────────────────────────────────────────────
        PrctlOption::SetName => {
            // In a real kernel, `arg2` is a user pointer to a
            // null-terminated string; copy_from_user would be used.
            // Stub: set an empty name.
            let _ = arg2;
            table.set_name(pid_idx, &[])?;
            Ok(0)
        }
        PrctlOption::GetName => {
            // In a real kernel, `arg2` is a user pointer where the
            // 16-byte name buffer is written via copy_to_user.
            let _ = arg2;
            Ok(0)
        }

        // ── Dumpable ──────────────────────────────────────────────
        PrctlOption::SetDumpable => {
            match arg2 {
                0 => table.set_dumpable(pid_idx, false)?,
                1 => table.set_dumpable(pid_idx, true)?,
                _ => return Err(Error::InvalidArgument),
            }
            Ok(0)
        }
        PrctlOption::GetDumpable => {
            let val = table.get_dumpable(pid_idx)?;
            Ok(u64::from(val))
        }

        // ── Seccomp ───────────────────────────────────────────────
        PrctlOption::SetSeccomp => {
            let mode = arg2 as u32;
            if mode > 2 {
                return Err(Error::InvalidArgument);
            }
            // Seccomp mode can only be tightened.
            let current = table.entries[pid_idx].seccomp_mode;
            if mode < current {
                return Err(Error::InvalidArgument);
            }
            table.entries[pid_idx].seccomp_mode = mode;
            Ok(0)
        }
        PrctlOption::GetSeccomp => {
            table.validate_idx(pid_idx)?;
            Ok(u64::from(table.entries[pid_idx].seccomp_mode))
        }

        // ── No-new-privileges ─────────────────────────────────────
        PrctlOption::SetNoNewPrivs => {
            if arg2 != 1 {
                return Err(Error::InvalidArgument);
            }
            table.set_no_new_privs(pid_idx)?;
            Ok(0)
        }
        PrctlOption::GetNoNewPrivs => {
            let val = table.get_no_new_privs(pid_idx)?;
            Ok(u64::from(val))
        }

        // ── Timer slack ───────────────────────────────────────────
        PrctlOption::SetTimerSlack => {
            table.set_timer_slack(pid_idx, arg2)?;
            Ok(0)
        }
        PrctlOption::GetTimerSlack => {
            let val = table.get_timer_slack(pid_idx)?;
            Ok(val)
        }

        // ── Child subreaper ───────────────────────────────────────
        PrctlOption::SetChildSubreaper => {
            table.set_child_subreaper(pid_idx, arg2 != 0)?;
            Ok(0)
        }
        PrctlOption::GetChildSubreaper => {
            let val = table.get_child_subreaper(pid_idx)?;
            Ok(u64::from(val))
        }

        // ── Parent-death signal ───────────────────────────────────
        PrctlOption::SetPdeathsig => {
            table.set_pdeathsig(pid_idx, arg2 as i32)?;
            Ok(0)
        }
        PrctlOption::GetPdeathsig => {
            let val = table.get_pdeathsig(pid_idx)?;
            Ok(val as u64)
        }

        // ── Capability bounding set ───────────────────────────────
        PrctlOption::CapBsetRead => {
            if arg2 > CAP_LAST_CAP {
                return Err(Error::InvalidArgument);
            }
            // Stub: report all capabilities as present.
            Ok(1)
        }
        PrctlOption::CapBsetDrop => {
            if arg2 > CAP_LAST_CAP {
                return Err(Error::InvalidArgument);
            }
            // Stub: accept the drop but don't persist it yet.
            Ok(0)
        }

        // ── Keep capabilities ─────────────────────────────────────
        PrctlOption::SetKeepCaps => {
            match arg2 {
                0 => table.set_keepcaps(pid_idx, false)?,
                1 => table.set_keepcaps(pid_idx, true)?,
                _ => return Err(Error::InvalidArgument),
            }
            Ok(0)
        }
        PrctlOption::GetKeepCaps => {
            let val = table.get_keepcaps(pid_idx)?;
            Ok(u64::from(val))
        }
    }
}
