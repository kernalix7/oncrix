// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended `waitid(2)` syscall handler with `waitpid` and `wait4` unification.
//!
//! Provides a unified wait interface that combines `waitid`, `waitpid`, and
//! `wait4` semantics into a single dispatcher.  This module is the primary
//! entry point for all process-wait syscalls in the ONCRIX kernel.
//!
//! # Operations
//!
//! | Syscall    | Handler            | Purpose                                 |
//! |------------|--------------------|-----------------------------------------|
//! | `waitid`   | [`sys_waitid`]     | POSIX.1-2024 wait with `idtype_t`       |
//! | `waitpid`  | [`sys_waitpid`]    | Traditional BSD/POSIX wait by PID       |
//! | `wait4`    | [`sys_wait4`]      | BSD wait with resource usage collection  |
//!
//! # POSIX conformance
//!
//! - `waitid`: POSIX.1-2024, Section `waitid()`
//! - `waitpid`: POSIX.1-2024, Section `waitpid()`
//! - At least one of `WEXITED`, `WSTOPPED`, or `WCONTINUED` must be set for
//!   `waitid`.
//! - `WNOHANG` causes immediate return when no status is available; the
//!   `siginfo` fields `si_signo` and `si_pid` are set to zero per POSIX.
//!
//! # References
//!
//! - POSIX.1-2024: `waitid()`, `waitpid()`, `sys/wait.h`
//! - Linux: `kernel/exit.c`, `include/uapi/linux/wait.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// WaitIdType — POSIX idtype_t
// ---------------------------------------------------------------------------

/// Identifier type for `waitid`, selecting which children to wait for.
///
/// Corresponds to POSIX `idtype_t`.  Values match the Linux ABI so that
/// the syscall layer can pass the raw integer directly.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitIdType {
    /// Wait for any child process (`id` is ignored).
    PAll = 0,
    /// Wait for the child whose PID equals `id`.
    PPid = 1,
    /// Wait for any child whose process group ID equals `id`.
    PPgid = 2,
    /// Wait for the child identified by the pidfd `id` (Linux extension).
    PPidfd = 3,
}

impl WaitIdType {
    /// Convert a raw `u32` to a typed [`WaitIdType`].
    ///
    /// Returns `Err(Error::InvalidArgument)` for unrecognised values.
    pub fn from_u32(val: u32) -> Result<Self> {
        match val {
            0 => Ok(Self::PAll),
            1 => Ok(Self::PPid),
            2 => Ok(Self::PPgid),
            3 => Ok(Self::PPidfd),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ---------------------------------------------------------------------------
// Wait option constants
// ---------------------------------------------------------------------------

/// Do not block if no child has changed state.
pub const WNOHANG: u32 = 0x0000_0001;
/// Report status of stopped children (waitpid).
pub const WUNTRACED: u32 = 0x0000_0002;
/// Wait for processes that have exited.
pub const WEXITED: u32 = 0x0000_0004;
/// Wait for processes that have continued from a stop.
pub const WCONTINUED: u32 = 0x0000_0008;
/// Leave the child in a waitable state (do not consume the event).
pub const WNOWAIT: u32 = 0x0100_0000;

/// Linux: also wait for cloned (non-child) tasks.
pub const __WCLONE: u32 = 0x8000_0000;
/// Linux: wait for any task regardless of clone flags.
pub const __WALL: u32 = 0x4000_0000;

/// Mask of all valid `waitid` flag bits.
const WAITID_FLAGS_ALL: u32 = WEXITED | WSTOPPED | WCONTINUED | WNOHANG | WNOWAIT;
/// Mask of state-selection flags for `waitid`.
const WAITID_STATE_FLAGS: u32 = WEXITED | WSTOPPED | WCONTINUED;

/// Wait for processes that have been stopped by a signal.
pub const WSTOPPED: u32 = 0x0000_0002;

/// All recognised `wait4` option bits.
const WAIT4_FLAGS_ALL: u32 = WNOHANG | WUNTRACED | WCONTINUED | __WCLONE | __WALL | WNOWAIT;

/// Maximum PID value accepted.
const PID_MAX: u32 = 4_194_304;

// ---------------------------------------------------------------------------
// SIGCHLD CLD codes
// ---------------------------------------------------------------------------

/// SIGCHLD signal number (x86_64 / generic Linux).
pub const SIGCHLD: i32 = 17;
/// Child has exited normally.
pub const CLD_EXITED: i32 = 1;
/// Child was killed by a signal.
pub const CLD_KILLED: i32 = 2;
/// Child was killed by a signal and produced a core dump.
pub const CLD_DUMPED: i32 = 3;
/// Child was stopped by a signal (ptrace trap).
pub const CLD_TRAPPED: i32 = 4;
/// Child has stopped (job control stop).
pub const CLD_STOPPED: i32 = 5;
/// Stopped child has continued.
pub const CLD_CONTINUED: i32 = 6;

// ---------------------------------------------------------------------------
// SigInfo — abbreviated siginfo_t for SIGCHLD reporting
// ---------------------------------------------------------------------------

/// Abbreviated `siginfo_t` for waitid child-status reporting.
///
/// Layout is `repr(C)` for direct copy to user space.  Fields follow
/// POSIX.1-2024 requirements for `si_signo`, `si_pid`, `si_uid`,
/// `si_status`, and `si_code` when the signal is `SIGCHLD`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SigInfo {
    /// Signal number (always [`SIGCHLD`] for waitid results).
    pub si_signo: i32,
    /// Exit status or signal number that caused the state change.
    pub si_status: i32,
    /// Signal code (one of the `CLD_*` constants).
    pub si_code: i32,
    /// PID of the child process.
    pub si_pid: u32,
    /// Real UID of the child process.
    pub si_uid: u32,
}

// ---------------------------------------------------------------------------
// WaitResult — unified result structure
// ---------------------------------------------------------------------------

/// Result of a successful wait call.
///
/// Contains the matched child's signal information, whether a match was
/// found (relevant for `WNOHANG`), and optional resource usage fields.
#[derive(Debug, Clone, Copy, Default)]
pub struct WaitResult {
    /// Whether a matching child was found.  When `WNOHANG` is set and
    /// no child has changed state, this is `false` and `siginfo`
    /// contains zeroed fields per POSIX.
    pub found: bool,
    /// Signal information for the child.
    pub siginfo: SigInfo,
    /// Encoded wait status (POSIX `wstatus` integer, for waitpid/wait4).
    pub wstatus: u32,
    /// User CPU time consumed by the child (microseconds).
    pub utime_usec: u64,
    /// System CPU time consumed by the child (microseconds).
    pub stime_usec: u64,
    /// Maximum resident set size (kilobytes).
    pub maxrss_kb: u64,
    /// Minor (soft) page faults.
    pub minflt: u64,
    /// Major (hard) page faults.
    pub majflt: u64,
}

// ---------------------------------------------------------------------------
// ChildState — lifecycle state as seen by wait
// ---------------------------------------------------------------------------

/// State change reportable by the wait family of syscalls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildState {
    /// Child exited normally with the given code.
    Exited(u8),
    /// Child was killed by a signal, optionally with a core dump.
    Signaled { signo: u32, core_dumped: bool },
    /// Child was stopped by the given signal.
    Stopped(u32),
    /// Child was resumed by `SIGCONT`.
    Continued,
}

impl ChildState {
    /// Encode this state as a POSIX wait status integer.
    pub const fn to_wstatus(self) -> u32 {
        match self {
            ChildState::Exited(code) => (code as u32) << 8,
            ChildState::Signaled { signo, core_dumped } => {
                (signo & 0x7F) | if core_dumped { 0x80 } else { 0 }
            }
            ChildState::Stopped(signo) => ((signo & 0xFF) << 8) | 0x7F,
            ChildState::Continued => 0xFFFF,
        }
    }

    /// Convert this state to a `CLD_*` code and status value.
    pub const fn to_cld_code_and_status(self) -> (i32, i32) {
        match self {
            ChildState::Exited(code) => (CLD_EXITED, code as i32),
            ChildState::Signaled { signo, core_dumped } => {
                let code = if core_dumped { CLD_DUMPED } else { CLD_KILLED };
                (code, signo as i32)
            }
            ChildState::Stopped(signo) => (CLD_STOPPED, signo as i32),
            ChildState::Continued => (CLD_CONTINUED, 0),
        }
    }

    /// Return `true` if this state matches a set of `waitid` option flags.
    pub const fn matches_options(self, options: u32) -> bool {
        match self {
            ChildState::Exited(_) | ChildState::Signaled { .. } => options & WEXITED != 0,
            ChildState::Stopped(_) => options & WSTOPPED != 0,
            ChildState::Continued => options & WCONTINUED != 0,
        }
    }
}

// ---------------------------------------------------------------------------
// WaitChildEntry — a waitable child process record
// ---------------------------------------------------------------------------

/// A waitable child process record.
#[derive(Debug, Clone)]
pub struct WaitChildEntry {
    /// Child PID.
    pub pid: u32,
    /// Parent PID.
    pub ppid: u32,
    /// Process group ID.
    pub pgid: u32,
    /// Real UID of the child.
    pub uid: u32,
    /// Current state.
    pub state: ChildState,
    /// Whether the state change has been consumed by a wait call.
    pub consumed: bool,
    /// User CPU time (microseconds).
    pub utime_usec: u64,
    /// System CPU time (microseconds).
    pub stime_usec: u64,
    /// Maximum resident set size (kilobytes).
    pub maxrss_kb: u64,
    /// Minor page faults.
    pub minflt: u64,
    /// Major page faults.
    pub majflt: u64,
}

impl WaitChildEntry {
    /// Create a new entry with zero resource usage.
    pub const fn new(pid: u32, ppid: u32, pgid: u32, uid: u32, state: ChildState) -> Self {
        Self {
            pid,
            ppid,
            pgid,
            uid,
            state,
            consumed: false,
            utime_usec: 0,
            stime_usec: 0,
            maxrss_kb: 0,
            minflt: 0,
            majflt: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// WaitChildTable — registry of waitable children
// ---------------------------------------------------------------------------

/// Maximum number of children tracked simultaneously.
pub const WAIT_TABLE_SIZE: usize = 128;

/// Registry of child processes that can be waited for.
pub struct WaitChildTable {
    entries: [Option<WaitChildEntry>; WAIT_TABLE_SIZE],
    count: usize,
}

impl WaitChildTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; WAIT_TABLE_SIZE],
            count: 0,
        }
    }

    /// Register a child process.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfMemory`] if the table is full.
    pub fn register(&mut self, entry: WaitChildEntry) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(entry);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a child entry (after it has been fully reaped).
    pub fn remove(&mut self, pid: u32) {
        for slot in self.entries.iter_mut() {
            if slot.as_ref().is_some_and(|e| e.pid == pid) {
                *slot = None;
                self.count = self.count.saturating_sub(1);
                return;
            }
        }
    }

    /// Update the state of a child.
    pub fn update_state(&mut self, pid: u32, new_state: ChildState) {
        for slot in self.entries.iter_mut() {
            if let Some(e) = slot {
                if e.pid == pid {
                    e.state = new_state;
                    e.consumed = false;
                    return;
                }
            }
        }
    }

    /// Return the number of tracked children.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return `true` if there are any children with the given parent.
    pub fn has_children_of(&self, parent_pid: u32) -> bool {
        self.entries
            .iter()
            .any(|s| s.as_ref().is_some_and(|e| e.ppid == parent_pid))
    }
}

impl Default for WaitChildTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate `waitid` flags.
///
/// Returns `Err(Error::InvalidArgument)` if unknown bits are set or
/// none of `WEXITED`, `WSTOPPED`, `WCONTINUED` are specified (per POSIX:
/// "Applications shall specify at least one of the flags").
fn validate_waitid_flags(flags: u32) -> Result<()> {
    if flags & !WAITID_FLAGS_ALL != 0 {
        return Err(Error::InvalidArgument);
    }
    if flags & WAITID_STATE_FLAGS == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate `wait4` option flags.
fn validate_wait4_options(options: u32) -> Result<()> {
    if options & !WAIT4_FLAGS_ALL != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// check_child_state — core matching logic
// ---------------------------------------------------------------------------

/// Check children in the table for a matching state change.
///
/// For `waitid` semantics, uses `WaitIdType`/`id` targeting.
/// Returns the table index of the first match, or `None`.
fn check_child_state_waitid(
    table: &WaitChildTable,
    idtype: WaitIdType,
    id: u64,
    options: u32,
    caller_pid: u32,
) -> Option<usize> {
    for (idx, slot) in table.entries.iter().enumerate() {
        let Some(entry) = slot.as_ref() else { continue };
        if entry.ppid != caller_pid {
            continue;
        }

        // ID filter.
        let id_match = match idtype {
            WaitIdType::PAll => true,
            WaitIdType::PPid => entry.pid == id as u32,
            WaitIdType::PPgid => entry.pgid == id as u32,
            WaitIdType::PPidfd => entry.pid == id as u32,
        };
        if !id_match {
            continue;
        }

        // State filter.
        if !entry.state.matches_options(options) {
            continue;
        }

        // Skip already consumed unless WNOWAIT.
        if entry.consumed && options & WNOWAIT == 0 {
            continue;
        }

        return Some(idx);
    }
    None
}

/// Check children for `wait4`/`waitpid` matching (pid_arg encoding).
fn check_child_state_wait4(
    table: &WaitChildTable,
    pid_arg: i32,
    options: u32,
    caller_pid: u32,
) -> Option<usize> {
    for (idx, slot) in table.entries.iter().enumerate() {
        let Some(entry) = slot.as_ref() else { continue };
        if entry.ppid != caller_pid {
            continue;
        }

        // PID filter per wait4 convention.
        let pid_match = match pid_arg {
            p if p > 0 => entry.pid == p as u32,
            0 => true,  // same process group (simplified)
            -1 => true, // any child
            p => {
                let pgid = (-p) as u32;
                entry.pgid == pgid
            }
        };
        if !pid_match {
            continue;
        }

        // State filter for wait4.
        let state_match = match entry.state {
            ChildState::Exited(_) | ChildState::Signaled { .. } => true,
            ChildState::Stopped(_) => options & WUNTRACED != 0,
            ChildState::Continued => options & WCONTINUED != 0,
        };
        if !state_match {
            continue;
        }

        if entry.consumed && options & WNOWAIT == 0 {
            continue;
        }

        return Some(idx);
    }
    None
}

/// Return `true` if any children exist matching the `waitid` filter.
fn has_matching_children_waitid(
    table: &WaitChildTable,
    idtype: WaitIdType,
    id: u64,
    caller_pid: u32,
) -> bool {
    table.entries.iter().any(|slot| {
        slot.as_ref().is_some_and(|e| {
            if e.ppid != caller_pid {
                return false;
            }
            match idtype {
                WaitIdType::PAll => true,
                WaitIdType::PPid => e.pid == id as u32,
                WaitIdType::PPgid => e.pgid == id as u32,
                WaitIdType::PPidfd => e.pid == id as u32,
            }
        })
    })
}

/// Return `true` if any children exist matching the `wait4` pid_arg filter.
fn has_matching_children_wait4(table: &WaitChildTable, pid_arg: i32, caller_pid: u32) -> bool {
    table.entries.iter().any(|slot| {
        slot.as_ref().is_some_and(|e| {
            if e.ppid != caller_pid {
                return false;
            }
            match pid_arg {
                p if p > 0 => e.pid == p as u32,
                0 => true,
                -1 => true,
                p => e.pgid == (-p) as u32,
            }
        })
    })
}

// ---------------------------------------------------------------------------
// Build a WaitResult from a matched entry
// ---------------------------------------------------------------------------

/// Build a [`WaitResult`] from a matched table entry.
fn build_result(entry: &WaitChildEntry) -> WaitResult {
    let (si_code, si_status) = entry.state.to_cld_code_and_status();
    WaitResult {
        found: true,
        siginfo: SigInfo {
            si_signo: SIGCHLD,
            si_status,
            si_code,
            si_pid: entry.pid,
            si_uid: entry.uid,
        },
        wstatus: entry.state.to_wstatus(),
        utime_usec: entry.utime_usec,
        stime_usec: entry.stime_usec,
        maxrss_kb: entry.maxrss_kb,
        minflt: entry.minflt,
        majflt: entry.majflt,
    }
}

// ---------------------------------------------------------------------------
// sys_waitid — POSIX.1-2024 waitid
// ---------------------------------------------------------------------------

/// `waitid` syscall handler (POSIX.1-2024).
///
/// Waits for a child process to change state, as identified by
/// `idtype` and `id`.
///
/// # Arguments
///
/// * `table`      — Wait child table.
/// * `idtype`     — Raw idtype_t value (0=P_ALL, 1=P_PID, 2=P_PGID, 3=P_PIDFD).
/// * `id`         — Target ID (PID, PGID, or pidfd depending on `idtype`).
/// * `options`    — Bitmask of `WEXITED`, `WSTOPPED`, `WCONTINUED`, `WNOHANG`,
///                  `WNOWAIT`.
/// * `caller_pid` — PID of the calling process.
///
/// # Returns
///
/// A [`WaitResult`] on success.  When `WNOHANG` is set and no child has
/// changed state, `found == false` and `siginfo` has zeroed `si_signo`
/// and `si_pid` per POSIX.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — invalid flags, idtype, or id.
/// * [`Error::NotFound`]        — no matching children exist (ECHILD).
/// * [`Error::Interrupted`]     — would block (simulated).
pub fn sys_waitid(
    table: &mut WaitChildTable,
    idtype: u32,
    id: u64,
    options: u32,
    caller_pid: u32,
) -> Result<WaitResult> {
    let id_type = WaitIdType::from_u32(idtype)?;
    validate_waitid_flags(options)?;

    // Validate id when targeting a specific process or group.
    match id_type {
        WaitIdType::PPid | WaitIdType::PPgid | WaitIdType::PPidfd => {
            if id == 0 || id > PID_MAX as u64 {
                return Err(Error::InvalidArgument);
            }
        }
        WaitIdType::PAll => { /* id is ignored */ }
    }

    // Check that matching children exist at all.
    if !has_matching_children_waitid(table, id_type, id, caller_pid) {
        return Err(Error::NotFound);
    }

    // Look for a waitable entry.
    if let Some(idx) = check_child_state_waitid(table, id_type, id, options, caller_pid) {
        let entry = table.entries[idx].as_mut().unwrap();
        let result = build_result(entry);

        let should_reap = options & WNOWAIT == 0
            && matches!(
                entry.state,
                ChildState::Exited(_) | ChildState::Signaled { .. }
            );

        if options & WNOWAIT == 0 {
            entry.consumed = true;
        }

        let pid = entry.pid;
        if should_reap {
            table.remove(pid);
        }

        return Ok(result);
    }

    // No waitable child found.
    if options & WNOHANG != 0 {
        // Per POSIX: si_signo and si_pid set to zero.
        Ok(WaitResult::default())
    } else {
        Err(Error::Interrupted)
    }
}

// ---------------------------------------------------------------------------
// sys_waitpid — traditional waitpid(2)
// ---------------------------------------------------------------------------

/// `waitpid` syscall handler.
///
/// Thin wrapper providing the traditional `waitpid` encoding:
///
/// | `pid_arg` | Meaning                                           |
/// |-----------|---------------------------------------------------|
/// | `> 0`     | Wait for the specific child with that PID         |
/// | `== 0`    | Wait for any child in the caller's process group  |
/// | `== -1`   | Wait for any child                                |
/// | `< -1`    | Wait for any child in process group `|pid_arg|`   |
///
/// # Returns
///
/// `(child_pid, wstatus)` on success.
///
/// # Errors
///
/// Same as [`sys_wait4`].
pub fn sys_waitpid(
    table: &mut WaitChildTable,
    pid_arg: i32,
    options: u32,
    caller_pid: u32,
) -> Result<(u32, u32)> {
    let result = sys_wait4(table, pid_arg, options, false, caller_pid)?;
    Ok((result.siginfo.si_pid, result.wstatus))
}

// ---------------------------------------------------------------------------
// sys_wait4 — BSD wait4(2) with resource usage
// ---------------------------------------------------------------------------

/// `wait4` syscall handler.
///
/// Waits for a child process to change state, with optional resource
/// usage collection.
///
/// # Arguments
///
/// * `table`       — Wait child table.
/// * `pid_arg`     — Child selector (see `sys_waitpid` for encoding).
/// * `options`     — Bitmask of `WNOHANG`, `WUNTRACED`, `WCONTINUED`, etc.
/// * `want_rusage` — Whether to include resource usage in the result.
/// * `caller_pid`  — PID of the calling process.
///
/// # Returns
///
/// A [`WaitResult`] on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — unknown option bits.
/// * [`Error::NotFound`]        — no matching children exist (ECHILD).
/// * [`Error::WouldBlock`]      — `WNOHANG` set and no waitable child.
/// * [`Error::Interrupted`]     — would block (simulated).
pub fn sys_wait4(
    table: &mut WaitChildTable,
    pid_arg: i32,
    options: u32,
    want_rusage: bool,
    caller_pid: u32,
) -> Result<WaitResult> {
    validate_wait4_options(options)?;

    // Check that matching children exist at all.
    if !has_matching_children_wait4(table, pid_arg, caller_pid) {
        return Err(Error::NotFound);
    }

    // Look for a waitable entry.
    if let Some(idx) = check_child_state_wait4(table, pid_arg, options, caller_pid) {
        let entry = table.entries[idx].as_mut().unwrap();
        let mut result = build_result(entry);

        // Clear rusage fields if not requested.
        if !want_rusage {
            result.utime_usec = 0;
            result.stime_usec = 0;
            result.maxrss_kb = 0;
            result.minflt = 0;
            result.majflt = 0;
        }

        let should_reap = options & WNOWAIT == 0
            && matches!(
                entry.state,
                ChildState::Exited(_) | ChildState::Signaled { .. }
            );

        if options & WNOWAIT == 0 {
            entry.consumed = true;
        }

        let pid = entry.pid;
        if should_reap {
            table.remove(pid);
        }

        return Ok(result);
    }

    // No waitable child found.
    if options & WNOHANG != 0 {
        Err(Error::WouldBlock)
    } else {
        Err(Error::Interrupted)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_table() -> WaitChildTable {
        let mut t = WaitChildTable::new();
        t.register(WaitChildEntry::new(10, 1, 5, 500, ChildState::Exited(0)))
            .unwrap();
        t.register(WaitChildEntry::new(11, 1, 5, 500, ChildState::Stopped(19)))
            .unwrap();
        t.register(WaitChildEntry::new(12, 1, 5, 500, ChildState::Continued))
            .unwrap();
        t.register(WaitChildEntry::new(20, 99, 7, 500, ChildState::Exited(1)))
            .unwrap();
        t
    }

    // --- sys_waitid ---

    #[test]
    fn waitid_any_exited() {
        let mut t = make_table();
        let r = sys_waitid(&mut t, 0, 0, WEXITED, 1).unwrap();
        assert!(r.found);
        assert_eq!(r.siginfo.si_pid, 10);
        assert_eq!(r.siginfo.si_code, CLD_EXITED);
        assert_eq!(r.siginfo.si_signo, SIGCHLD);
    }

    #[test]
    fn waitid_specific_pid() {
        let mut t = make_table();
        let r = sys_waitid(&mut t, 1, 10, WEXITED, 1).unwrap();
        assert!(r.found);
        assert_eq!(r.siginfo.si_pid, 10);
    }

    #[test]
    fn waitid_no_state_flags_rejected() {
        let mut t = make_table();
        assert_eq!(
            sys_waitid(&mut t, 0, 0, WNOHANG, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn waitid_wnohang_no_match() {
        let mut t = WaitChildTable::new();
        t.register(WaitChildEntry::new(10, 1, 5, 500, ChildState::Stopped(19)))
            .unwrap();
        // Only WEXITED set, child is stopped => no match.
        let r = sys_waitid(&mut t, 0, 0, WEXITED | WNOHANG, 1).unwrap();
        assert!(!r.found);
        assert_eq!(r.siginfo.si_signo, 0);
        assert_eq!(r.siginfo.si_pid, 0);
    }

    #[test]
    fn waitid_no_children_returns_notfound() {
        let mut t = WaitChildTable::new();
        assert_eq!(sys_waitid(&mut t, 0, 0, WEXITED, 1), Err(Error::NotFound));
    }

    #[test]
    fn waitid_stopped_with_wstopped() {
        let mut t = make_table();
        let r = sys_waitid(&mut t, 1, 11, WSTOPPED, 1).unwrap();
        assert!(r.found);
        assert_eq!(r.siginfo.si_pid, 11);
        assert_eq!(r.siginfo.si_code, CLD_STOPPED);
    }

    #[test]
    fn waitid_continued_with_wcontinued() {
        let mut t = make_table();
        let r = sys_waitid(&mut t, 1, 12, WCONTINUED, 1).unwrap();
        assert!(r.found);
        assert_eq!(r.siginfo.si_pid, 12);
        assert_eq!(r.siginfo.si_code, CLD_CONTINUED);
    }

    #[test]
    fn waitid_wnowait_does_not_reap() {
        let mut t = WaitChildTable::new();
        t.register(WaitChildEntry::new(10, 1, 5, 500, ChildState::Exited(0)))
            .unwrap();
        sys_waitid(&mut t, 0, 0, WEXITED | WNOWAIT, 1).unwrap();
        // Child still exists.
        assert_eq!(t.count(), 1);
    }

    #[test]
    fn waitid_reaps_exited_child() {
        let mut t = WaitChildTable::new();
        t.register(WaitChildEntry::new(10, 1, 5, 500, ChildState::Exited(42)))
            .unwrap();
        let r = sys_waitid(&mut t, 0, 0, WEXITED, 1).unwrap();
        assert_eq!(r.siginfo.si_status, 42);
        assert_eq!(t.count(), 0);
    }

    #[test]
    fn waitid_foreign_child_not_visible() {
        let mut t = make_table();
        assert_eq!(sys_waitid(&mut t, 1, 20, WEXITED, 1), Err(Error::NotFound));
    }

    #[test]
    fn waitid_pgid_match() {
        let mut t = make_table();
        let r = sys_waitid(&mut t, 2, 5, WEXITED, 1).unwrap();
        assert!(r.found);
        assert_eq!(r.siginfo.si_pid, 10);
    }

    // --- sys_waitpid ---

    #[test]
    fn waitpid_any_child() {
        let mut t = make_table();
        let (pid, status) = sys_waitpid(&mut t, -1, 0, 1).unwrap();
        assert_eq!(pid, 10);
        assert!((status & 0x7F) == 0); // WIFEXITED
    }

    #[test]
    fn waitpid_specific() {
        let mut t = make_table();
        let (pid, _) = sys_waitpid(&mut t, 10, 0, 1).unwrap();
        assert_eq!(pid, 10);
    }

    #[test]
    fn waitpid_not_found() {
        let mut t = make_table();
        assert_eq!(sys_waitpid(&mut t, 9999, 0, 1), Err(Error::NotFound));
    }

    // --- sys_wait4 ---

    #[test]
    fn wait4_with_rusage() {
        let mut t = WaitChildTable::new();
        let mut child = WaitChildEntry::new(10, 1, 5, 500, ChildState::Exited(0));
        child.utime_usec = 500;
        child.stime_usec = 200;
        t.register(child).unwrap();
        let r = sys_wait4(&mut t, -1, 0, true, 1).unwrap();
        assert_eq!(r.utime_usec, 500);
        assert_eq!(r.stime_usec, 200);
    }

    #[test]
    fn wait4_without_rusage() {
        let mut t = WaitChildTable::new();
        let mut child = WaitChildEntry::new(10, 1, 5, 500, ChildState::Exited(0));
        child.utime_usec = 500;
        t.register(child).unwrap();
        let r = sys_wait4(&mut t, -1, 0, false, 1).unwrap();
        assert_eq!(r.utime_usec, 0);
    }

    #[test]
    fn wait4_invalid_options() {
        let mut t = make_table();
        assert_eq!(
            sys_wait4(&mut t, -1, 0xDEAD_0000, false, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn wait4_wnohang_no_match() {
        let mut t = WaitChildTable::new();
        t.register(WaitChildEntry::new(10, 1, 5, 500, ChildState::Stopped(19)))
            .unwrap();
        assert_eq!(
            sys_wait4(&mut t, -1, WNOHANG, false, 1),
            Err(Error::WouldBlock)
        );
    }

    #[test]
    fn wait4_by_pgid() {
        let mut t = WaitChildTable::new();
        t.register(WaitChildEntry::new(50, 1, 42, 500, ChildState::Exited(0)))
            .unwrap();
        let r = sys_wait4(&mut t, -42, 0, false, 1).unwrap();
        assert_eq!(r.siginfo.si_pid, 50);
    }

    // --- WaitChildTable ---

    #[test]
    fn table_update_state() {
        let mut t = WaitChildTable::new();
        t.register(WaitChildEntry::new(10, 1, 5, 500, ChildState::Stopped(19)))
            .unwrap();
        t.update_state(10, ChildState::Continued);
        let r = sys_waitid(&mut t, 1, 10, WCONTINUED, 1).unwrap();
        assert_eq!(r.siginfo.si_code, CLD_CONTINUED);
    }
}
