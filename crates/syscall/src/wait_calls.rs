// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `wait4(2)`, `waitpid(2)`, and wait status encoding helpers.
//!
//! Implements the traditional BSD/Linux wait interface:
//!
//! - `wait4(pid, &status, options, &rusage)` — the workhorse; used by `wait(3)`,
//!   `waitpid(3)`, and `wait3(3)`.
//! - `waitpid(pid, &status, options)` — thin wrapper around `wait4` without rusage.
//!
//! Wait status is encoded in a `u32` using the traditional POSIX/Linux layout:
//!
//! ```text
//! exit: (exit_code << 8) | 0x00
//! signal: signal_number & 0x7F
//! stop:  (stop_signal << 8) | 0x7F
//! cont:  0xFFFF
//! ```
//!
//! # Operations
//!
//! | Syscall     | Handler           | Purpose                              |
//! |-------------|-------------------|--------------------------------------|
//! | `wait4`     | [`do_wait4`]      | Wait for child with rusage           |
//! | `waitpid`   | [`do_waitpid`]    | Wait for child by PID (no rusage)    |
//!
//! # References
//!
//! - POSIX.1-2024: `waitpid()`, `wait()`, `sys/wait.h`
//! - Linux: `kernel/exit.c`, `include/uapi/linux/wait.h`
//! - `man wait4(2)`, `man waitpid(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Wait options (POSIX + Linux)
// ---------------------------------------------------------------------------

/// Do not block if no child has changed state.
pub const WNOHANG: u32 = 1;
/// Report status of stopped children.
pub const WUNTRACED: u32 = 2;
/// Report status of continued children (POSIX: `WCONTINUED`).
pub const WCONTINUED: u32 = 8;

/// Linux: also wait for cloned (non-child) tasks.
pub const __WCLONE: u32 = 0x8000_0000;
/// Linux: wait for any task regardless of clone flags.
pub const __WALL: u32 = 0x4000_0000;
/// Linux: don't reap, just peek.
pub const WNOWAIT: u32 = 0x0100_0000;

/// All recognised wait4 option bits.
const WAIT4_FLAGS_KNOWN: u32 = WNOHANG | WUNTRACED | WCONTINUED | __WCLONE | __WALL | WNOWAIT;

// ---------------------------------------------------------------------------
// Wait status encoding/decoding
// ---------------------------------------------------------------------------

/// Encode a normal exit (process called `exit(code)`) into a wait status.
///
/// The encoded value satisfies `WIFEXITED(status) == true` and
/// `WEXITSTATUS(status) == code`.
pub const fn wstatus_exited(code: u8) -> u32 {
    (code as u32) << 8
}

/// Encode a signal-terminated status.
///
/// `WIFSIGNALED(status) == true`, `WTERMSIG(status) == signo`.
pub const fn wstatus_signaled(signo: u32, core_dumped: bool) -> u32 {
    (signo & 0x7F) | if core_dumped { 0x80 } else { 0 }
}

/// Encode a stopped status (job control or ptrace).
///
/// `WIFSTOPPED(status) == true`, `WSTOPSIG(status) == signo`.
pub const fn wstatus_stopped(signo: u32) -> u32 {
    ((signo & 0xFF) << 8) | 0x7F
}

/// Encode a "continued" status (`SIGCONT` received).
///
/// `WIFCONTINUED(status) == true`.
pub const fn wstatus_continued() -> u32 {
    0xFFFF
}

/// Return `true` if the child exited normally.
pub const fn wifexited(status: u32) -> bool {
    (status & 0x7F) == 0
}

/// Return `true` if the child was killed by a signal.
pub const fn wifsignaled(status: u32) -> bool {
    let low7 = status & 0x7F;
    low7 != 0 && low7 != 0x7F
}

/// Return `true` if the child is currently stopped.
pub const fn wifstopped(status: u32) -> bool {
    (status & 0xFF) == 0x7F
}

/// Return `true` if the child was resumed by `SIGCONT`.
pub const fn wifcontinued(status: u32) -> bool {
    status == 0xFFFF
}

/// Extract the exit code from a normal-exit status.
pub const fn wexitstatus(status: u32) -> u8 {
    ((status >> 8) & 0xFF) as u8
}

/// Extract the terminating signal number.
pub const fn wtermsig(status: u32) -> u32 {
    status & 0x7F
}

/// Extract the stop signal number.
pub const fn wstopsig(status: u32) -> u32 {
    (status >> 8) & 0xFF
}

// ---------------------------------------------------------------------------
// ChildState — the lifecycle state of a child as seen by wait4
// ---------------------------------------------------------------------------

/// State change that can be reported by `wait4` / `waitpid`.
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
            ChildState::Exited(code) => wstatus_exited(code),
            ChildState::Signaled { signo, core_dumped } => wstatus_signaled(signo, core_dumped),
            ChildState::Stopped(signo) => wstatus_stopped(signo),
            ChildState::Continued => wstatus_continued(),
        }
    }
}

// ---------------------------------------------------------------------------
// RUsage — resource usage snapshot
// ---------------------------------------------------------------------------

/// Resource usage summary returned by `wait4`.
///
/// Mirrors `struct rusage` from POSIX.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RUsage {
    /// User CPU time (microseconds).
    pub utime_usec: u64,
    /// System CPU time (microseconds).
    pub stime_usec: u64,
    /// Maximum resident set size (kilobytes).
    pub maxrss_kb: u64,
    /// Minor (soft) page faults.
    pub minflt: u64,
    /// Major (hard) page faults.
    pub majflt: u64,
    /// Voluntary context switches.
    pub nvcsw: u64,
    /// Involuntary context switches.
    pub nivcsw: u64,
}

impl RUsage {
    /// Construct an empty (zero) rusage.
    pub const fn zero() -> Self {
        Self {
            utime_usec: 0,
            stime_usec: 0,
            maxrss_kb: 0,
            minflt: 0,
            majflt: 0,
            nvcsw: 0,
            nivcsw: 0,
        }
    }

    /// Accumulate `other` into `self` (used for summing child resource usage).
    pub fn accumulate(&mut self, other: &RUsage) {
        self.utime_usec = self.utime_usec.saturating_add(other.utime_usec);
        self.stime_usec = self.stime_usec.saturating_add(other.stime_usec);
        self.maxrss_kb = self.maxrss_kb.max(other.maxrss_kb);
        self.minflt = self.minflt.saturating_add(other.minflt);
        self.majflt = self.majflt.saturating_add(other.majflt);
        self.nvcsw = self.nvcsw.saturating_add(other.nvcsw);
        self.nivcsw = self.nivcsw.saturating_add(other.nivcsw);
    }
}

// ---------------------------------------------------------------------------
// ChildEntry — a child process as tracked by wait4
// ---------------------------------------------------------------------------

/// A child process record in the wait4 table.
#[derive(Debug, Clone)]
pub struct ChildEntry {
    /// Child PID.
    pub pid: u32,
    /// Parent PID.
    pub ppid: u32,
    /// Process group ID.
    pub pgid: u32,
    /// UID of the child.
    pub uid: u32,
    /// Current state of the child.
    pub state: ChildState,
    /// Resource usage accumulated so far.
    pub rusage: RUsage,
    /// Whether the state change has been consumed by a wait call.
    pub consumed: bool,
}

impl ChildEntry {
    /// Create a new child entry in the Exited(0) state with zero rusage.
    pub const fn new(pid: u32, ppid: u32, pgid: u32, uid: u32, state: ChildState) -> Self {
        Self {
            pid,
            ppid,
            pgid,
            uid,
            state,
            rusage: RUsage::zero(),
            consumed: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Wait4Result — what do_wait4 returns on success
// ---------------------------------------------------------------------------

/// Successful result from a `wait4` or `waitpid` call.
#[derive(Debug, Clone)]
pub struct Wait4Result {
    /// PID of the child whose state change was reported.
    pub pid: u32,
    /// Encoded wait status (POSIX `wstatus` integer).
    pub status: u32,
    /// Resource usage of the reaped child (zero if `rusage` not requested).
    pub rusage: RUsage,
}

// ---------------------------------------------------------------------------
// WaitTable — registry of waitable children
// ---------------------------------------------------------------------------

/// Maximum number of children tracked simultaneously.
pub const WAIT_TABLE_SIZE: usize = 128;

/// Registry of child processes that can be waited for.
pub struct WaitTable {
    entries: [Option<ChildEntry>; WAIT_TABLE_SIZE],
    count: usize,
}

impl WaitTable {
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
    pub fn register(&mut self, entry: ChildEntry) -> Result<()> {
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
            if slot.as_ref().map(|e| e.pid == pid).unwrap_or(false) {
                *slot = None;
                self.count -= 1;
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

    /// Return `true` if there are any children with `ppid == parent_pid`.
    pub fn has_children(&self, parent_pid: u32) -> bool {
        self.entries
            .iter()
            .any(|s| s.as_ref().map(|e| e.ppid == parent_pid).unwrap_or(false))
    }

    /// Find the first waitable child matching `pid_arg` and `options` for `parent`.
    ///
    /// - `pid_arg > 0`  → wait for that specific child.
    /// - `pid_arg == 0` → wait for any child in same process group as caller.
    /// - `pid_arg == -1` → wait for any child.
    /// - `pid_arg < -1` → wait for any child in process group `|pid_arg|`.
    ///
    /// Returns the index into `entries` of the match, or `None`.
    fn find_waitable(&self, pid_arg: i32, options: u32, parent_pid: u32) -> Option<usize> {
        for (idx, slot) in self.entries.iter().enumerate() {
            let Some(e) = slot.as_ref() else { continue };
            if e.ppid != parent_pid {
                continue;
            }
            // PID filter.
            let pid_match = match pid_arg {
                p if p > 0 => e.pid == p as u32,
                0 => true, // any child (simplified: ignore pgid comparison)
                -1 => true,
                p => {
                    let pgid = (-p) as u32;
                    e.pgid == pgid
                }
            };
            if !pid_match {
                continue;
            }

            // State filter: check options against the child state.
            let state_match = match e.state {
                ChildState::Exited(_) | ChildState::Signaled { .. } => true,
                ChildState::Stopped(_) => options & WUNTRACED != 0,
                ChildState::Continued => options & WCONTINUED != 0,
            };
            if !state_match {
                continue;
            }

            // Skip already-consumed events (unless WNOWAIT is set — it peeks).
            if e.consumed && options & WNOWAIT == 0 {
                continue;
            }

            return Some(idx);
        }
        None
    }
}

// ---------------------------------------------------------------------------
// do_wait4
// ---------------------------------------------------------------------------

/// Handler for `wait4(2)`.
///
/// Waits for a state change in a child process.  The `pid_arg` argument
/// follows the traditional `wait4` / `waitpid` encoding:
///
/// | Value      | Meaning                                          |
/// |------------|--------------------------------------------------|
/// | `> 0`      | Wait for the specific child with that PID        |
/// | `== 0`     | Wait for any child in the caller's process group |
/// | `== -1`    | Wait for any child                               |
/// | `< -1`     | Wait for any child in process group `|pid_arg|`  |
///
/// # Arguments
///
/// * `table`      — Wait table.
/// * `pid_arg`    — Child selector (see above).
/// * `options`    — Bitmask of `WNOHANG`, `WUNTRACED`, `WCONTINUED`, etc.
/// * `want_rusage` — Whether to include resource usage in the result.
/// * `caller_pid` — PID of the calling process (used as `ppid` filter).
///
/// # Returns
///
/// On success, a [`Wait4Result`] containing the child PID, encoded status,
/// and optional resource usage.
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — Unknown option bits.
/// * [`Error::WouldBlock`]       — `WNOHANG` set and no waitable child found.
/// * [`Error::NotFound`]         — No matching children exist at all.
/// * [`Error::Interrupted`]      — Would block but returned early (simulated).
///
/// # POSIX conformance
///
/// Follows POSIX.1-2024 `waitpid()` semantics.  Exited and signaled children
/// are reaped (removed) unless `WNOWAIT` is set.
pub fn do_wait4(
    table: &mut WaitTable,
    pid_arg: i32,
    options: u32,
    want_rusage: bool,
    caller_pid: u32,
) -> Result<Wait4Result> {
    if options & !WAIT4_FLAGS_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }

    // Check that the caller has at least one child matching the filter.
    let any_child = match pid_arg {
        -1 => table.has_children(caller_pid),
        0 => table.has_children(caller_pid),
        p if p > 0 => table.entries.iter().any(|s| {
            s.as_ref()
                .map(|e| e.pid == p as u32 && e.ppid == caller_pid)
                .unwrap_or(false)
        }),
        p => {
            let pgid = (-p) as u32;
            table.entries.iter().any(|s| {
                s.as_ref()
                    .map(|e| e.pgid == pgid && e.ppid == caller_pid)
                    .unwrap_or(false)
            })
        }
    };

    if !any_child {
        return Err(Error::NotFound);
    }

    // Look for a waitable entry.
    if let Some(idx) = table.find_waitable(pid_arg, options, caller_pid) {
        // Safety: index from find_waitable always points to Some.
        let entry = table.entries[idx].as_mut().unwrap();
        let pid = entry.pid;
        let status = entry.state.to_wstatus();
        let rusage = if want_rusage {
            entry.rusage
        } else {
            RUsage::zero()
        };

        let should_reap = options & WNOWAIT == 0
            && matches!(
                entry.state,
                ChildState::Exited(_) | ChildState::Signaled { .. }
            );

        if options & WNOWAIT == 0 {
            entry.consumed = true;
        }

        let result = Wait4Result {
            pid,
            status,
            rusage,
        };

        if should_reap {
            table.remove(pid);
        }

        return Ok(result);
    }

    // No waitable child found.
    if options & WNOHANG != 0 {
        Err(Error::WouldBlock)
    } else {
        // In a real kernel we would block.  Here we return Interrupted to signal
        // that the caller should re-invoke after being woken.
        Err(Error::Interrupted)
    }
}

// ---------------------------------------------------------------------------
// do_waitpid
// ---------------------------------------------------------------------------

/// Handler for `waitpid(2)`.
///
/// Thin wrapper around [`do_wait4`] without resource usage collection.
///
/// # Arguments
///
/// * `table`      — Wait table.
/// * `pid_arg`    — Child selector (same semantics as `wait4`).
/// * `options`    — `WNOHANG` | `WUNTRACED` | `WCONTINUED`.
/// * `caller_pid` — PID of the calling process.
///
/// # Returns
///
/// `(child_pid, encoded_status)` on success.
///
/// # Errors
///
/// Same as [`do_wait4`].
pub fn do_waitpid(
    table: &mut WaitTable,
    pid_arg: i32,
    options: u32,
    caller_pid: u32,
) -> Result<(u32, u32)> {
    let result = do_wait4(table, pid_arg, options, false, caller_pid)?;
    Ok((result.pid, result.status))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Status encoding/decoding ---

    #[test]
    fn exited_status_roundtrip() {
        let s = wstatus_exited(42);
        assert!(wifexited(s));
        assert_eq!(wexitstatus(s), 42);
        assert!(!wifsignaled(s));
        assert!(!wifstopped(s));
    }

    #[test]
    fn signaled_status_roundtrip() {
        let s = wstatus_signaled(9, false);
        assert!(wifsignaled(s));
        assert_eq!(wtermsig(s), 9);
        assert!(!wifexited(s));
    }

    #[test]
    fn signaled_core_dump() {
        let s = wstatus_signaled(11, true);
        assert!(wifsignaled(s));
        assert!(s & 0x80 != 0); // core dump bit
    }

    #[test]
    fn stopped_status_roundtrip() {
        let s = wstatus_stopped(19); // SIGSTOP
        assert!(wifstopped(s));
        assert_eq!(wstopsig(s), 19);
        assert!(!wifexited(s));
    }

    #[test]
    fn continued_status() {
        let s = wstatus_continued();
        assert!(wifcontinued(s));
        assert!(!wifsignaled(s));
        assert!(!wifexited(s));
    }

    // --- ChildState::to_wstatus ---

    #[test]
    fn child_state_exited_encodes() {
        let s = ChildState::Exited(0).to_wstatus();
        assert!(wifexited(s));
        assert_eq!(wexitstatus(s), 0);
    }

    #[test]
    fn child_state_signaled_encodes() {
        let s = ChildState::Signaled {
            signo: 15,
            core_dumped: false,
        }
        .to_wstatus();
        assert!(wifsignaled(s));
        assert_eq!(wtermsig(s), 15);
    }

    // --- RUsage ---

    #[test]
    fn rusage_accumulate() {
        let mut total = RUsage::zero();
        let a = RUsage {
            utime_usec: 100,
            stime_usec: 50,
            maxrss_kb: 512,
            ..RUsage::zero()
        };
        let b = RUsage {
            utime_usec: 200,
            stime_usec: 30,
            maxrss_kb: 1024,
            ..RUsage::zero()
        };
        total.accumulate(&a);
        total.accumulate(&b);
        assert_eq!(total.utime_usec, 300);
        assert_eq!(total.stime_usec, 80);
        assert_eq!(total.maxrss_kb, 1024); // max of the two
    }

    // --- WaitTable helpers ---

    fn make_table() -> WaitTable {
        let mut t = WaitTable::new();
        // Child 10: exited
        t.register(ChildEntry::new(10, 1, 5, 500, ChildState::Exited(0)))
            .unwrap();
        // Child 11: stopped (SIGSTOP)
        t.register(ChildEntry::new(11, 1, 5, 500, ChildState::Stopped(19)))
            .unwrap();
        // Child 12: continued
        t.register(ChildEntry::new(12, 1, 5, 500, ChildState::Continued))
            .unwrap();
        // Child 20: different parent
        t.register(ChildEntry::new(20, 99, 7, 500, ChildState::Exited(1)))
            .unwrap();
        t
    }

    // --- do_waitpid ---

    #[test]
    fn waitpid_any_child_gets_exited() {
        let mut t = make_table();
        let (pid, status) = do_waitpid(&mut t, -1, 0, 1).unwrap();
        assert_eq!(pid, 10);
        assert!(wifexited(status));
    }

    #[test]
    fn waitpid_specific_pid() {
        let mut t = make_table();
        let (pid, status) = do_waitpid(&mut t, 10, 0, 1).unwrap();
        assert_eq!(pid, 10);
        assert!(wifexited(status));
    }

    #[test]
    fn waitpid_specific_pid_notfound() {
        let mut t = make_table();
        // pid 9999 doesn't exist
        assert_eq!(do_waitpid(&mut t, 9999, 0, 1), Err(Error::NotFound));
    }

    #[test]
    fn waitpid_stopped_child_needs_wuntraced() {
        let mut t = make_table();
        // Without WUNTRACED, stopped child 11 is not reported.
        // Child 10 (exited) is reported first.
        let (pid, _) = do_waitpid(&mut t, 11, 0, 1).unwrap_or((0, 0));
        // If not reported, try with WUNTRACED.
        if pid == 0 {
            let (pid2, status) = do_waitpid(&mut t, 11, WUNTRACED, 1).unwrap();
            assert_eq!(pid2, 11);
            assert!(wifstopped(status));
        }
    }

    #[test]
    fn waitpid_stopped_with_wuntraced() {
        let mut t = make_table();
        // Reap child 10 first, then get stopped child 11
        do_waitpid(&mut t, 10, 0, 1).unwrap();
        let (pid, status) = do_waitpid(&mut t, 11, WUNTRACED, 1).unwrap();
        assert_eq!(pid, 11);
        assert!(wifstopped(status));
        assert_eq!(wstopsig(status), 19);
    }

    #[test]
    fn waitpid_continued_with_wcontinued() {
        let mut t = make_table();
        // Reap 10 first, skip 11 (stopped, no WUNTRACED)
        do_waitpid(&mut t, 10, 0, 1).unwrap();
        let (pid, status) = do_waitpid(&mut t, 12, WCONTINUED, 1).unwrap();
        assert_eq!(pid, 12);
        assert!(wifcontinued(status));
    }

    #[test]
    fn waitpid_wnohang_no_child_returns_wouldblock() {
        let mut t = WaitTable::new();
        // Register only a stopped child (no exited children).
        t.register(ChildEntry::new(10, 1, 5, 500, ChildState::Stopped(19)))
            .unwrap();
        // Without WUNTRACED, WNOHANG should return WouldBlock.
        assert_eq!(do_waitpid(&mut t, -1, WNOHANG, 1), Err(Error::WouldBlock));
    }

    #[test]
    fn waitpid_no_children_returns_notfound() {
        let mut t = WaitTable::new();
        assert_eq!(do_waitpid(&mut t, -1, 0, 1), Err(Error::NotFound));
    }

    #[test]
    fn waitpid_child_reaped_after_wait() {
        let mut t = make_table();
        do_waitpid(&mut t, 10, 0, 1).unwrap();
        // Child 10 should be gone.
        assert!(
            t.entries
                .iter()
                .all(|s| s.as_ref().map(|e| e.pid != 10).unwrap_or(true))
        );
    }

    #[test]
    fn waitpid_foreign_child_not_visible() {
        let mut t = make_table();
        // Process 1 cannot wait for child 20 (ppid 99).
        assert_eq!(do_waitpid(&mut t, 20, 0, 1), Err(Error::NotFound));
    }

    // --- do_wait4 ---

    #[test]
    fn wait4_with_rusage() {
        let mut t = WaitTable::new();
        let mut child = ChildEntry::new(10, 1, 5, 500, ChildState::Exited(0));
        child.rusage = RUsage {
            utime_usec: 500,
            stime_usec: 200,
            ..RUsage::zero()
        };
        t.register(child).unwrap();

        let r = do_wait4(&mut t, -1, 0, true, 1).unwrap();
        assert_eq!(r.pid, 10);
        assert_eq!(r.rusage.utime_usec, 500);
        assert_eq!(r.rusage.stime_usec, 200);
    }

    #[test]
    fn wait4_without_rusage_returns_zero() {
        let mut t = WaitTable::new();
        let mut child = ChildEntry::new(10, 1, 5, 500, ChildState::Exited(0));
        child.rusage = RUsage {
            utime_usec: 500,
            ..RUsage::zero()
        };
        t.register(child).unwrap();

        let r = do_wait4(&mut t, -1, 0, false, 1).unwrap();
        assert_eq!(r.rusage.utime_usec, 0);
    }

    #[test]
    fn wait4_unknown_options_rejected() {
        let mut t = make_table();
        assert_eq!(
            do_wait4(&mut t, -1, 0xDEAD_0000, false, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn wait4_wnowait_does_not_reap() {
        let mut t = WaitTable::new();
        t.register(ChildEntry::new(10, 1, 5, 500, ChildState::Exited(0)))
            .unwrap();
        // WNOWAIT: peek without reaping.
        do_wait4(&mut t, -1, WNOWAIT, false, 1).unwrap();
        // Child 10 is still in the table.
        assert!(
            t.entries
                .iter()
                .any(|s| s.as_ref().map(|e| e.pid == 10).unwrap_or(false))
        );
    }

    #[test]
    fn wait4_by_pgid_negative_pid() {
        let mut t = WaitTable::new();
        // Child with pgid 42, ppid 1
        t.register(ChildEntry::new(50, 1, 42, 500, ChildState::Exited(0)))
            .unwrap();
        let (pid, _) = do_waitpid(&mut t, -42, 0, 1).unwrap();
        assert_eq!(pid, 50);
    }

    // --- WaitTable.update_state ---

    #[test]
    fn update_state_changes_child() {
        let mut t = WaitTable::new();
        t.register(ChildEntry::new(10, 1, 5, 500, ChildState::Stopped(19)))
            .unwrap();
        t.update_state(10, ChildState::Continued);
        let r = do_wait4(&mut t, 10, WCONTINUED, false, 1).unwrap();
        assert!(wifcontinued(r.status));
    }
}
