// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sigaction(2)`, `sigprocmask(2)`, and `sigpending(2)` syscall handlers.
//!
//! Implements the POSIX signal disposition and mask management interface.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `sigaction()`, `sigprocmask()`, `sigpending()`.
//! Key behaviours:
//! - `sigaction` atomically installs a new handler and/or retrieves the old one.
//! - `SA_RESTART`  — restart syscalls interrupted by this signal.
//! - `SA_SIGINFO`  — deliver extended `siginfo_t` to the handler.
//! - `SA_NODEFER`  — do not mask the signal while its handler runs.
//! - `SA_RESETHAND`— reset the handler to `SIG_DFL` after delivery.
//! - `SA_NOCLDWAIT`— do not create zombies for `SIGCHLD`.
//! - `sigprocmask(SIG_BLOCK)`   — add signals to the blocked mask.
//! - `sigprocmask(SIG_UNBLOCK)` — remove signals from the blocked mask.
//! - `sigprocmask(SIG_SETMASK)` — replace the blocked mask.
//! - `SIGKILL` and `SIGSTOP` cannot be blocked or have their handler changed.
//! - `sigpending` returns signals that are pending delivery.
//!
//! # References
//!
//! - POSIX.1-2024: `sigaction()`, `sigprocmask()`, `sigpending()`
//! - Linux man pages: `sigaction(2)`, `sigprocmask(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Signal constants
// ---------------------------------------------------------------------------

/// Total number of signal entries (1-indexed; index 0 unused).
pub const NSIG: usize = 65;

/// Signal 9: SIGKILL (cannot be caught or blocked).
pub const SIGKILL: u32 = 9;
/// Signal 19: SIGSTOP (cannot be caught or blocked).
pub const SIGSTOP: u32 = 19;

// ---------------------------------------------------------------------------
// SA_* flags
// ---------------------------------------------------------------------------

/// Restart syscalls interrupted by this signal.
pub const SA_RESTART: u32 = 0x1000_0000;
/// Deliver extended `siginfo_t` to the handler.
pub const SA_SIGINFO: u32 = 0x0000_0004;
/// Do not automatically mask the signal while the handler runs.
pub const SA_NODEFER: u32 = 0x4000_0000;
/// Reset handler to `SIG_DFL` after delivery (one-shot).
pub const SA_RESETHAND: u32 = 0x8000_0000;
/// Do not create zombie children for `SIGCHLD`.
pub const SA_NOCLDWAIT: u32 = 0x0000_0002;
/// Use alternate signal stack.
pub const SA_ONSTACK: u32 = 0x0800_0000;

/// All known SA flags.
const SA_KNOWN: u32 =
    SA_RESTART | SA_SIGINFO | SA_NODEFER | SA_RESETHAND | SA_NOCLDWAIT | SA_ONSTACK;

// ---------------------------------------------------------------------------
// Signal handler disposition
// ---------------------------------------------------------------------------

/// Signal handler disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigHandler {
    /// Default kernel action.
    Default,
    /// Ignore the signal.
    Ignore,
    /// User-space handler function at this virtual address.
    Handler(u64),
}

/// A complete signal action installed via `sigaction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigAction {
    /// Signal handler disposition.
    pub handler: SigHandler,
    /// `SA_*` flags.
    pub flags: u32,
    /// Signals to additionally mask while this handler runs.
    pub mask: u64,
}

impl Default for SigAction {
    fn default() -> Self {
        Self {
            handler: SigHandler::Default,
            flags: 0,
            mask: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Signal action table
// ---------------------------------------------------------------------------

/// Per-process signal action table.
pub struct SigActionTable {
    actions: [SigAction; NSIG],
}

impl Default for SigActionTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SigActionTable {
    /// Create with all signals set to `SIG_DFL`.
    pub fn new() -> Self {
        Self {
            actions: [const {
                SigAction {
                    handler: SigHandler::Default,
                    flags: 0,
                    mask: 0,
                }
            }; NSIG],
        }
    }

    /// Return the current action for `signo`.
    pub fn get(&self, signo: u32) -> Option<&SigAction> {
        if signo == 0 || signo as usize >= NSIG {
            return None;
        }
        Some(&self.actions[signo as usize])
    }

    /// Set the action for `signo`.
    fn set(&mut self, signo: u32, action: SigAction) {
        if signo > 0 && (signo as usize) < NSIG {
            self.actions[signo as usize] = action;
        }
    }
}

// ---------------------------------------------------------------------------
// sigaction handler
// ---------------------------------------------------------------------------

/// Handler for `sigaction(2)`.
///
/// Atomically retrieves the old action and/or installs `new_action` for
/// signal `signo`.
///
/// # Arguments
///
/// * `table`      — The per-process signal action table.
/// * `signo`      — Signal number.
/// * `new_action` — `Some(action)` to install; `None` to just query.
///
/// # Returns
///
/// The previous `SigAction` for `signo`.
///
/// # Errors
///
/// | `Error`    | Condition                                              |
/// |------------|--------------------------------------------------------|
/// | `InvalidArg` | `signo` is 0 or ≥ `NSIG`                            |
/// | `InvalidArg` | Unknown `SA_*` flags in `new_action.flags`           |
/// | `AccessDenied`| Attempt to change disposition of `SIGKILL`/`SIGSTOP`|
pub fn do_sigaction(
    table: &mut SigActionTable,
    signo: u32,
    new_action: Option<SigAction>,
) -> Result<SigAction> {
    if signo == 0 || signo as usize >= NSIG {
        return Err(Error::InvalidArgument);
    }

    let old = *table.get(signo).unwrap();

    if let Some(action) = new_action {
        // SIGKILL and SIGSTOP cannot be overridden.
        if signo == SIGKILL || signo == SIGSTOP {
            return Err(Error::PermissionDenied);
        }
        // Validate flags.
        if action.flags & !SA_KNOWN != 0 {
            return Err(Error::InvalidArgument);
        }
        table.set(signo, action);
    }

    Ok(old)
}

// ---------------------------------------------------------------------------
// sigprocmask
// ---------------------------------------------------------------------------

/// `sigprocmask(2)` how argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigmaskHow {
    /// Add `set` to the current blocked mask.
    Block,
    /// Remove `set` from the current blocked mask.
    Unblock,
    /// Replace the current blocked mask with `set`.
    SetMask,
}

/// Linux ABI values for `how`.
pub const SIG_BLOCK: i32 = 0;
pub const SIG_UNBLOCK: i32 = 1;
pub const SIG_SETMASK: i32 = 2;

/// Parse a raw `how` integer.
pub fn parse_sigmask_how(how: i32) -> Result<SigmaskHow> {
    match how {
        SIG_BLOCK => Ok(SigmaskHow::Block),
        SIG_UNBLOCK => Ok(SigmaskHow::Unblock),
        SIG_SETMASK => Ok(SigmaskHow::SetMask),
        _ => Err(Error::InvalidArgument),
    }
}

/// Handler for `sigprocmask(2)`.
///
/// Updates `blocked` according to `how` and `set`.  Returns the old blocked
/// mask.  `SIGKILL` and `SIGSTOP` bits in `set` are silently ignored.
///
/// # Errors
///
/// | `Error`    | Condition                     |
/// |------------|-------------------------------|
/// | `InvalidArg` | `how` is not valid          |
pub fn do_sigprocmask(blocked: &mut u64, how: i32, set: Option<u64>) -> Result<u64> {
    let old = *blocked;

    if let Some(mask) = set {
        let how_parsed = parse_sigmask_how(how)?;
        // Clear SIGKILL / SIGSTOP bits — cannot be blocked.
        let clean_mask = mask & !(1u64 << (SIGKILL - 1)) & !(1u64 << (SIGSTOP - 1));

        *blocked = match how_parsed {
            SigmaskHow::Block => old | clean_mask,
            SigmaskHow::Unblock => old & !clean_mask,
            SigmaskHow::SetMask => clean_mask,
        };
    }

    Ok(old)
}

// ---------------------------------------------------------------------------
// sigpending
// ---------------------------------------------------------------------------

/// Handler for `sigpending(2)`.
///
/// Returns the set of signals that are pending delivery to the calling thread
/// (blocked and queued).
///
/// `pending_mask` is the bitmask of signals that have been sent but are
/// currently blocked.
pub fn do_sigpending(pending_mask: u64) -> u64 {
    pending_mask
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn handler_action(addr: u64) -> SigAction {
        SigAction {
            handler: SigHandler::Handler(addr),
            flags: SA_RESTART,
            mask: 0,
        }
    }

    #[test]
    fn sigaction_install_and_retrieve() {
        let mut table = SigActionTable::new();
        let old = do_sigaction(&mut table, 15, Some(handler_action(0xDEAD))).unwrap();
        assert_eq!(old.handler, SigHandler::Default);
        let current = do_sigaction(&mut table, 15, None).unwrap();
        assert_eq!(current.handler, SigHandler::Handler(0xDEAD));
    }

    #[test]
    fn sigaction_sigkill_denied() {
        let mut table = SigActionTable::new();
        assert_eq!(
            do_sigaction(&mut table, SIGKILL, Some(handler_action(0x1000))),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn sigaction_invalid_signo() {
        let mut table = SigActionTable::new();
        assert_eq!(
            do_sigaction(&mut table, 0, None),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            do_sigaction(&mut table, NSIG as u32, None),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn sigprocmask_block() {
        let mut blocked: u64 = 0;
        let old = do_sigprocmask(&mut blocked, SIG_BLOCK, Some(0b1100)).unwrap();
        assert_eq!(old, 0);
        assert_eq!(blocked, 0b1100);
    }

    #[test]
    fn sigprocmask_unblock() {
        let mut blocked: u64 = 0b1111;
        do_sigprocmask(&mut blocked, SIG_UNBLOCK, Some(0b0110)).unwrap();
        assert_eq!(blocked, 0b1001);
    }

    #[test]
    fn sigprocmask_setmask() {
        let mut blocked: u64 = 0xFFFF;
        do_sigprocmask(&mut blocked, SIG_SETMASK, Some(0b1010)).unwrap();
        assert_eq!(blocked & 0b1111, 0b1010);
    }

    #[test]
    fn sigprocmask_cannot_block_sigkill() {
        let mut blocked: u64 = 0;
        // Bit for SIGKILL = bit (9-1) = bit 8.
        let kill_bit = 1u64 << (SIGKILL - 1);
        do_sigprocmask(&mut blocked, SIG_BLOCK, Some(kill_bit)).unwrap();
        assert_eq!(blocked & kill_bit, 0);
    }

    #[test]
    fn sigpending_returns_mask() {
        assert_eq!(do_sigpending(0b11010), 0b11010);
    }
}
