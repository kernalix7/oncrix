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
/// Get the securebits flags.
pub const PR_GET_SECUREBITS: i32 = 27;
/// Set the securebits flags.
pub const PR_SET_SECUREBITS: i32 = 28;

// ── Securebits bit definitions (Linux-compatible) ──────────────────────────

/// If set, a process that has one or more 0 UIDs keeps its capabilities when
/// it switches all UIDs to non-zero.
pub const SECBIT_KEEP_CAPS: u64 = 1 << 4;
/// Lock bit for [`SECBIT_KEEP_CAPS`]; once set it cannot be cleared.
pub const SECBIT_KEEP_CAPS_LOCKED: u64 = 1 << 5;
/// If set, the kernel does not grant capabilities when a setuid-root program
/// is executed (no-root behaviour).
pub const SECBIT_NOROOT: u64 = 1 << 0;
/// Lock bit for [`SECBIT_NOROOT`]; once set it cannot be cleared.
pub const SECBIT_NOROOT_LOCKED: u64 = 1 << 1;
/// If set, capabilities are not raised when executing a file with the setuid
/// bit set or with file capabilities (no-setuid-fixup behaviour).
pub const SECBIT_NO_SETUID_FIXUP: u64 = 1 << 2;
/// Lock bit for [`SECBIT_NO_SETUID_FIXUP`]; once set it cannot be cleared.
pub const SECBIT_NO_SETUID_FIXUP_LOCKED: u64 = 1 << 3;

/// Mask of all securebits "locked" bits. A locked bit, once set, is one-way:
/// it can never be cleared, and the value bit it guards can never change.
const SECBITS_LOCK_MASK: u64 =
    SECBIT_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP_LOCKED | SECBIT_KEEP_CAPS_LOCKED;

/// Mask of every defined securebit (value + lock). Any bit outside this mask
/// is rejected so unknown/future bits cannot be smuggled in.
const SECBITS_ALL_MASK: u64 = SECBIT_NOROOT
    | SECBIT_NOROOT_LOCKED
    | SECBIT_NO_SETUID_FIXUP
    | SECBIT_NO_SETUID_FIXUP_LOCKED
    | SECBIT_KEEP_CAPS
    | SECBIT_KEEP_CAPS_LOCKED;

/// Maximum length of a process name (excluding null terminator).
const PRCTL_NAME_MAX: usize = 15;

/// Total name buffer size (15 usable bytes + null terminator).
const PRCTL_NAME_BUF: usize = 16;

/// Maximum PID table entries.
const MAX_PRCTL_ENTRIES: usize = 256;

/// Default timer slack (50 microseconds in nanoseconds, matches Linux).
const DEFAULT_TIMER_SLACK_NS: u64 = 50_000;

/// Highest valid Linux capability number (`CAP_LAST_CAP`).
const CAP_LAST_CAP: u64 = 40;

/// Capability number for `CAP_SETPCAP`, required to drop bounding-set caps and
/// to alter securebits. Matches the Linux capability numbering.
///
/// Exposed so the syscall dispatcher can compute the `has_cap_setpcap`
/// argument to [`do_prctl`] from the caller's effective capability set.
pub const CAP_SETPCAP: u64 = 8;

/// Full capability bounding set: bit `n` set for every valid capability
/// (`0..=CAP_LAST_CAP`). Used as the default per-process bounding set.
const CAP_BSET_FULL: u64 = if CAP_LAST_CAP >= 63 {
    u64::MAX
} else {
    (1u64 << (CAP_LAST_CAP + 1)) - 1
};

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
    /// Set the securebits flags.
    SetSecurebits,
    /// Get the securebits flags.
    GetSecurebits,
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
            PR_SET_SECUREBITS => Ok(Self::SetSecurebits),
            PR_GET_SECUREBITS => Ok(Self::GetSecurebits),
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
    /// Capability bounding-set bitmask: bit `n` set means capability `n` is
    /// still present. Capabilities can only be dropped (cleared), never added.
    cap_bset: u64,
    /// Securebits flags (see `SECBIT_*`). Bits in [`SECBITS_LOCK_MASK`] are
    /// one-way: once set they (and the value bit they guard) can never change.
    securebits: u64,
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
            cap_bset: CAP_BSET_FULL,
            securebits: 0,
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

    // ── Capability bounding set ───────────────────────────────────

    /// Returns whether capability `cap` is present in `pid_idx`'s bounding set.
    ///
    /// `cap` must be in `0..=CAP_LAST_CAP`; out-of-range values are rejected
    /// to avoid shifting past the bitmask width.
    pub fn cap_bset_read(&self, pid_idx: usize, cap: u64) -> Result<bool> {
        self.validate_idx(pid_idx)?;
        if cap > CAP_LAST_CAP {
            return Err(Error::InvalidArgument);
        }
        Ok((self.entries[pid_idx].cap_bset & (1u64 << cap)) != 0)
    }

    /// Drops capability `cap` from `pid_idx`'s bounding set (one-way).
    ///
    /// SECURITY: the caller must already hold `CAP_SETPCAP`; this is enforced
    /// by the dispatcher before calling. Dropping is irreversible — a cleared
    /// bit can never be restored through this interface.
    pub fn cap_bset_drop(&mut self, pid_idx: usize, cap: u64) -> Result<()> {
        self.validate_idx(pid_idx)?;
        if cap > CAP_LAST_CAP {
            return Err(Error::InvalidArgument);
        }
        self.entries[pid_idx].cap_bset &= !(1u64 << cap);
        Ok(())
    }

    // ── Securebits ────────────────────────────────────────────────

    /// Get the securebits flags for `pid_idx`.
    pub fn get_securebits(&self, pid_idx: usize) -> Result<u64> {
        self.validate_idx(pid_idx)?;
        Ok(self.entries[pid_idx].securebits)
    }

    /// Set the securebits flags for `pid_idx`.
    ///
    /// SECURITY: this enforces the one-way locking semantics — no bit guarded
    /// by an already-set lock bit (nor the lock bit itself) may change, and no
    /// undefined bit may be set. The capability check (`CAP_SETPCAP`) is the
    /// caller's responsibility and is enforced by the dispatcher.
    pub fn set_securebits(&mut self, pid_idx: usize, new_bits: u64) -> Result<()> {
        self.validate_idx(pid_idx)?;
        // Reject any bit outside the defined securebits set.
        if new_bits & !SECBITS_ALL_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        let current = self.entries[pid_idx].securebits;
        // For every lock bit that is already set, neither that lock bit nor the
        // value bit immediately below it (lock = value << 1) may change.
        let locked = current & SECBITS_LOCK_MASK;
        // Build a frozen-bit mask: each set lock bit freezes itself and its
        // paired value bit (the value bit sits one position lower).
        let frozen = locked | (locked >> 1);
        if (current & frozen) != (new_bits & frozen) {
            return Err(Error::PermissionDenied);
        }
        self.entries[pid_idx].securebits = new_bits;
        Ok(())
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
/// SECURITY: `has_cap_setpcap` must reflect whether the *calling* process
/// holds `CAP_SETPCAP`. It gates the privileged operations
/// (`PR_CAP_BSET_DROP`, `PR_SET_SECUREBITS`); callers must compute it from the
/// caller's effective capability set, never assume `true`.
///
/// # Returns
///
/// - `PR_SET_*` operations return `0` on success.
/// - `PR_GET_*` operations return the requested value as `u64`.
/// - Unknown or invalid options return `Error::InvalidArgument`.
/// - Privileged operations without `CAP_SETPCAP` return
///   `Error::PermissionDenied`.
// The prctl ABI is inherently wide (option + arg2..arg5 + caller context);
// the extra `has_cap_setpcap` credential is required to enforce the privileged
// gates, so the argument count is by design.
#[allow(clippy::too_many_arguments)]
pub fn do_prctl(
    table: &mut PrctlTable,
    option: i32,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    pid_idx: usize,
    has_cap_setpcap: bool,
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
            // SECURITY: bound the PID slot before any table read/write. Every
            // other set branch goes through validate_idx; this one indexed the
            // table directly, so an out-of-range pid_idx was an OOB access.
            table.validate_idx(pid_idx)?;
            // SECURITY: validate the raw u64 arg before truncating to u32 so a
            // high-bit-only value (e.g. 0x1_0000_0000) cannot alias a valid
            // low mode after truncation.
            if arg2 > 2 {
                return Err(Error::InvalidArgument);
            }
            let mode = arg2 as u32;
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
            // SECURITY: no_new_privs is strictly one-way. We only accept the
            // value 1 (set); there is no code path that clears it, and
            // set_no_new_privs only ever writes `true`. A 0->1 transition is
            // the only legal change.
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
            // SECURITY: bound the cap number (cap_bset_read also re-checks) and
            // report the *actual* bounding-set bit, not a hard-coded 1. A
            // constant 1 would hide caps that have been dropped.
            let present = table.cap_bset_read(pid_idx, arg2)?;
            Ok(u64::from(present))
        }
        PrctlOption::CapBsetDrop => {
            // SECURITY: dropping a bounding-set capability requires CAP_SETPCAP.
            // Without this gate any process could shrink the bounding set; more
            // importantly the previous stub returned Ok without enforcing it.
            if !has_cap_setpcap {
                return Err(Error::PermissionDenied);
            }
            // Bound the cap number, then persist the (one-way) drop.
            table.cap_bset_drop(pid_idx, arg2)?;
            Ok(0)
        }

        // ── Keep capabilities ─────────────────────────────────────
        PrctlOption::SetKeepCaps => {
            table.validate_idx(pid_idx)?;
            // SECURITY: if SECBIT_KEEP_CAPS is locked, the keepcaps state is
            // frozen and PR_SET_KEEPCAPS must not be able to flip it.
            if table.entries[pid_idx].securebits & SECBIT_KEEP_CAPS_LOCKED != 0 {
                return Err(Error::PermissionDenied);
            }
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

        // ── Securebits ────────────────────────────────────────────
        PrctlOption::SetSecurebits => {
            // SECURITY: changing securebits is privileged (CAP_SETPCAP). The
            // previous code did not implement this option at all; failing to
            // gate it would let any process clear NOROOT/NO_SETUID_FIXUP and
            // regain root-on-exec semantics.
            if !has_cap_setpcap {
                return Err(Error::PermissionDenied);
            }
            // set_securebits enforces the one-way LOCKED-bit semantics and
            // rejects undefined bits.
            table.set_securebits(pid_idx, arg2)?;
            Ok(0)
        }
        PrctlOption::GetSecurebits => {
            let val = table.get_securebits(pid_idx)?;
            Ok(val)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> PrctlTable {
        let mut t = PrctlTable::default();
        t.init_for_pid(0).unwrap();
        t
    }

    #[test]
    fn seccomp_out_of_range_pid_idx_rejected() {
        // SetSeccomp must bound-check the slot, not OOB-index the table.
        let mut t = table();
        let r = do_prctl(&mut t, PR_SET_SECCOMP, 1, 0, 0, 0, MAX_PRCTL_ENTRIES, false);
        assert_eq!(r.unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn seccomp_high_bits_truncation_rejected() {
        // A value whose low 32 bits are a valid mode but with high bits set
        // must be rejected before truncation to u32.
        let mut t = table();
        let r = do_prctl(&mut t, PR_SET_SECCOMP, 0x1_0000_0001, 0, 0, 0, 0, false);
        assert_eq!(r.unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn cap_bset_drop_requires_setpcap() {
        let mut t = table();
        // Without CAP_SETPCAP: denied.
        assert_eq!(
            do_prctl(&mut t, PR_CAP_BSET_DROP, CAP_SETPCAP, 0, 0, 0, 0, false).unwrap_err(),
            Error::PermissionDenied
        );
        // Cap still present after the denied drop.
        assert_eq!(
            do_prctl(&mut t, PR_CAP_BSET_READ, CAP_SETPCAP, 0, 0, 0, 0, false).unwrap(),
            1
        );
    }

    #[test]
    fn cap_bset_drop_persists_with_setpcap() {
        let mut t = table();
        // With CAP_SETPCAP the drop succeeds and persists.
        assert_eq!(
            do_prctl(&mut t, PR_CAP_BSET_DROP, 5, 0, 0, 0, 0, true).unwrap(),
            0
        );
        assert_eq!(
            do_prctl(&mut t, PR_CAP_BSET_READ, 5, 0, 0, 0, 0, false).unwrap(),
            0
        );
    }

    #[test]
    fn cap_bset_read_out_of_range_rejected() {
        let mut t = table();
        let r = do_prctl(
            &mut t,
            PR_CAP_BSET_READ,
            CAP_LAST_CAP + 1,
            0,
            0,
            0,
            0,
            false,
        );
        assert_eq!(r.unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn securebits_requires_setpcap() {
        let mut t = table();
        let r = do_prctl(&mut t, PR_SET_SECUREBITS, SECBIT_NOROOT, 0, 0, 0, 0, false);
        assert_eq!(r.unwrap_err(), Error::PermissionDenied);
    }

    #[test]
    fn securebits_locked_bit_is_one_way() {
        let mut t = table();
        // Set NOROOT and lock it (privileged).
        do_prctl(
            &mut t,
            PR_SET_SECUREBITS,
            SECBIT_NOROOT | SECBIT_NOROOT_LOCKED,
            0,
            0,
            0,
            0,
            true,
        )
        .unwrap();
        // Attempt to clear NOROOT (and its lock) now fails: locked is one-way.
        let r = do_prctl(&mut t, PR_SET_SECUREBITS, 0, 0, 0, 0, 0, true);
        assert_eq!(r.unwrap_err(), Error::PermissionDenied);
        // Value is unchanged.
        assert_eq!(
            do_prctl(&mut t, PR_GET_SECUREBITS, 0, 0, 0, 0, 0, false).unwrap(),
            SECBIT_NOROOT | SECBIT_NOROOT_LOCKED
        );
    }

    #[test]
    fn securebits_undefined_bit_rejected() {
        let mut t = table();
        // Bit 63 is not a defined securebit.
        let r = do_prctl(&mut t, PR_SET_SECUREBITS, 1 << 63, 0, 0, 0, 0, true);
        assert_eq!(r.unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn keepcaps_frozen_when_locked() {
        let mut t = table();
        // Lock KEEP_CAPS via securebits.
        do_prctl(
            &mut t,
            PR_SET_SECUREBITS,
            SECBIT_KEEP_CAPS | SECBIT_KEEP_CAPS_LOCKED,
            0,
            0,
            0,
            0,
            true,
        )
        .unwrap();
        // PR_SET_KEEPCAPS must not be able to flip the frozen state.
        let r = do_prctl(&mut t, PR_SET_KEEPCAPS, 0, 0, 0, 0, 0, false);
        assert_eq!(r.unwrap_err(), Error::PermissionDenied);
    }

    #[test]
    fn no_new_privs_is_one_way() {
        let mut t = table();
        // Only 0->1 is permitted; clearing (arg2 == 0) is rejected outright.
        assert_eq!(
            do_prctl(&mut t, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0, false).unwrap(),
            0
        );
        let r = do_prctl(&mut t, PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0, 0, false);
        assert_eq!(r.unwrap_err(), Error::InvalidArgument);
        // Still set.
        assert_eq!(
            do_prctl(&mut t, PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0, 0, false).unwrap(),
            1
        );
    }
}
