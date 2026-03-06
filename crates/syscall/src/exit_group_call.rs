// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `exit_group(2)` syscall handler.
//!
//! Terminates all threads in the calling process's thread group with the
//! same exit status.  This is the standard way to exit a multi-threaded
//! process; the C library `exit(3)` function calls `exit_group` rather than
//! the single-thread `exit(2)` syscall.
//!
//! # Syscall signature
//!
//! ```text
//! void exit_group(int status);
//! ```
//!
//! # POSIX reference
//!
//! POSIX.1-2024 `_exit()` — terminates the process; `exit_group` is the
//! Linux-specific multi-thread extension.
//!
//! # References
//!
//! - Linux: `kernel/exit.c` `do_group_exit()`
//! - `exit_group(2)` man page

use oncrix_lib::Result;

// ---------------------------------------------------------------------------
// Exit status encoding
// ---------------------------------------------------------------------------

/// Mask applied to the user-provided status to derive the low byte.
const EXIT_STATUS_MASK: i32 = 0xFF;

/// Maximum raw exit status value passable to `exit_group`.
pub const EXIT_STATUS_MAX: i32 = 255;

// ---------------------------------------------------------------------------
// ExitCode — type-safe wrapper
// ---------------------------------------------------------------------------

/// Type-safe exit code.
///
/// Only the low 8 bits of the raw status are visible to the parent via
/// `wait(2)`.  Higher bits are masked before storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExitCode(u8);

impl ExitCode {
    /// Wrap a raw status (masks to low byte).
    pub const fn from_raw(raw: i32) -> Self {
        Self((raw & EXIT_STATUS_MASK) as u8)
    }

    /// Return the raw `u8` value.
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// Return `true` if this represents a successful exit (code 0).
    pub const fn is_success(self) -> bool {
        self.0 == 0
    }

    /// Encode into the wait-status word format used by `waitpid`.
    ///
    /// A normal exit encodes the exit code in bits 8..=15 of the status word.
    pub const fn to_wait_status(self) -> i32 {
        (self.0 as i32) << 8
    }
}

// ---------------------------------------------------------------------------
// ThreadGroupExit — per-thread-group exit state
// ---------------------------------------------------------------------------

/// Reason for a thread group exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    /// Process called `exit_group` explicitly.
    Normal(ExitCode),
    /// A fatal signal killed the thread group.
    Signal(u32),
}

/// State of a thread group undergoing `exit_group`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadGroupExitState {
    /// Not exiting.
    Running,
    /// In the process of exiting; threads are being terminated.
    Exiting(ExitReason),
    /// All threads have exited; process is a zombie.
    Zombie(ExitReason),
}

/// Per-thread-group exit record.
///
/// Tracks the exit reason and per-thread termination progress so that the
/// kernel can reap the zombie once the parent calls `wait`.
#[derive(Debug, Clone, Copy)]
pub struct ThreadGroupExitRecord {
    /// Thread group ID.
    pub tgid: u64,
    /// Exit state.
    pub state: ThreadGroupExitState,
    /// Total thread count at exit initiation.
    pub thread_count: u32,
    /// Threads that have already reached `do_exit`.
    pub threads_exited: u32,
}

impl ThreadGroupExitRecord {
    /// Create a new record for a running thread group.
    pub const fn new(tgid: u64, thread_count: u32) -> Self {
        Self {
            tgid,
            state: ThreadGroupExitState::Running,
            thread_count,
            threads_exited: 0,
        }
    }

    /// Mark another thread as having completed `do_exit`.
    ///
    /// Returns `true` when the last thread has exited and the process
    /// transitions to `Zombie`.
    pub fn thread_exited(&mut self) -> bool {
        self.threads_exited = self.threads_exited.saturating_add(1);
        if self.threads_exited >= self.thread_count {
            if let ThreadGroupExitState::Exiting(reason) = self.state {
                self.state = ThreadGroupExitState::Zombie(reason);
                return true;
            }
        }
        false
    }

    /// Return `true` if the thread group is currently exiting or zombie.
    pub const fn is_dying(&self) -> bool {
        !matches!(self.state, ThreadGroupExitState::Running)
    }
}

// ---------------------------------------------------------------------------
// ExitGroupTable — tracks ongoing exits
// ---------------------------------------------------------------------------

/// Maximum number of simultaneously exiting thread groups tracked.
const MAX_EXITS: usize = 64;

/// Sentinel value indicating an empty slot.
const EMPTY_TGID: u64 = 0;

/// Table of in-progress `exit_group` operations.
pub struct ExitGroupTable {
    records: [ThreadGroupExitRecord; MAX_EXITS],
    count: usize,
}

impl ExitGroupTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            records: [const {
                ThreadGroupExitRecord {
                    tgid: EMPTY_TGID,
                    state: ThreadGroupExitState::Running,
                    thread_count: 0,
                    threads_exited: 0,
                }
            }; MAX_EXITS],
            count: 0,
        }
    }

    /// Return the number of in-progress exits.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if the table is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Initiate `exit_group` for `tgid`.
    ///
    /// If the thread group is already exiting, the call is a no-op (the first
    /// exit status wins).
    ///
    /// Returns `Err(Error::OutOfMemory)` if the table is full.
    pub fn initiate(&mut self, tgid: u64, thread_count: u32, code: ExitCode) -> Result<()> {
        use oncrix_lib::Error;

        // Already exiting?
        if let Some(rec) = self.find_mut(tgid) {
            if rec.is_dying() {
                return Ok(());
            }
            rec.state = ThreadGroupExitState::Exiting(ExitReason::Normal(code));
            return Ok(());
        }

        // New entry.
        let slot = self
            .records
            .iter()
            .position(|r| r.tgid == EMPTY_TGID)
            .ok_or(Error::OutOfMemory)?;

        self.records[slot] = ThreadGroupExitRecord {
            tgid,
            state: ThreadGroupExitState::Exiting(ExitReason::Normal(code)),
            thread_count,
            threads_exited: 0,
        };
        self.count += 1;
        Ok(())
    }

    /// Record that one thread in `tgid` has completed `do_exit`.
    ///
    /// Returns `true` when the process is now a zombie.
    pub fn thread_did_exit(&mut self, tgid: u64) -> bool {
        if let Some(rec) = self.find_mut(tgid) {
            return rec.thread_exited();
        }
        false
    }

    /// Remove a zombie entry after the parent has reaped it.
    pub fn reap(&mut self, tgid: u64) -> Option<ExitReason> {
        for rec in &mut self.records {
            if rec.tgid == tgid {
                if let ThreadGroupExitState::Zombie(reason) = rec.state {
                    rec.tgid = EMPTY_TGID;
                    rec.state = ThreadGroupExitState::Running;
                    self.count = self.count.saturating_sub(1);
                    return Some(reason);
                }
            }
        }
        None
    }

    /// Find a record by TGID (mutable).
    fn find_mut(&mut self, tgid: u64) -> Option<&mut ThreadGroupExitRecord> {
        self.records.iter_mut().find(|r| r.tgid == tgid)
    }

    /// Find a record by TGID (shared).
    pub fn find(&self, tgid: u64) -> Option<&ThreadGroupExitRecord> {
        self.records.iter().find(|r| r.tgid == tgid)
    }
}

impl Default for ExitGroupTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// sys_exit_group — syscall entry point
// ---------------------------------------------------------------------------

/// Handler for `exit_group(2)`.
///
/// Initiates termination of all threads in the calling thread group with
/// exit status `status & 0xFF`.
///
/// This function records the exit in the table and returns `Ok(ExitCode)`.
/// The caller is responsible for delivering `SIGKILL` to sibling threads and
/// eventually transitioning the process to zombie state.
///
/// # Arguments
///
/// * `table`        — `ExitGroupTable` tracking ongoing exits.
/// * `tgid`         — Thread group ID of the caller.
/// * `thread_count` — Number of live threads in the group.
/// * `status`       — Exit status (only low 8 bits used).
///
/// # Returns
///
/// `Ok(ExitCode)` — the masked exit code that will be visible to the parent.
pub fn sys_exit_group(
    table: &mut ExitGroupTable,
    tgid: u64,
    thread_count: u32,
    status: i32,
) -> Result<ExitCode> {
    let code = ExitCode::from_raw(status);
    table.initiate(tgid, thread_count, code)?;
    Ok(code)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_masking() {
        assert_eq!(ExitCode::from_raw(0).as_u8(), 0);
        assert_eq!(ExitCode::from_raw(1).as_u8(), 1);
        assert_eq!(ExitCode::from_raw(255).as_u8(), 255);
        // High bits are masked.
        assert_eq!(ExitCode::from_raw(256).as_u8(), 0);
        assert_eq!(ExitCode::from_raw(257).as_u8(), 1);
    }

    #[test]
    fn exit_code_success() {
        assert!(ExitCode::from_raw(0).is_success());
        assert!(!ExitCode::from_raw(1).is_success());
    }

    #[test]
    fn exit_code_wait_status() {
        assert_eq!(ExitCode::from_raw(42).to_wait_status(), 42 << 8);
    }

    #[test]
    fn sys_exit_group_records_exit() {
        let mut t = ExitGroupTable::new();
        let code = sys_exit_group(&mut t, 100, 3, 0).unwrap();
        assert!(code.is_success());
        let rec = t.find(100).unwrap();
        assert!(rec.is_dying());
    }

    #[test]
    fn double_exit_group_noop() {
        let mut t = ExitGroupTable::new();
        sys_exit_group(&mut t, 100, 1, 0).unwrap();
        // Second call should not panic or error.
        sys_exit_group(&mut t, 100, 1, 1).unwrap();
        // First exit status wins; the record still shows code 0.
        let rec = t.find(100).unwrap();
        assert!(
            matches!(rec.state, ThreadGroupExitState::Exiting(ExitReason::Normal(c)) if c.as_u8() == 0)
        );
    }

    #[test]
    fn thread_exit_transitions_to_zombie() {
        let mut t = ExitGroupTable::new();
        sys_exit_group(&mut t, 200, 2, 42).unwrap();
        assert!(!t.thread_did_exit(200)); // 1 of 2 done.
        assert!(t.thread_did_exit(200)); // 2 of 2 done → zombie.
        let rec = t.find(200).unwrap();
        assert!(matches!(rec.state, ThreadGroupExitState::Zombie(_)));
    }

    #[test]
    fn reap_removes_zombie() {
        let mut t = ExitGroupTable::new();
        sys_exit_group(&mut t, 300, 1, 5).unwrap();
        t.thread_did_exit(300);
        let reason = t.reap(300).unwrap();
        assert!(matches!(reason, ExitReason::Normal(c) if c.as_u8() == 5));
        assert!(t.find(300).is_none());
    }

    #[test]
    fn table_full_returns_oom() {
        use oncrix_lib::Error;
        let mut t = ExitGroupTable::new();
        for i in 1..=(64u64) {
            let _ = sys_exit_group(&mut t, i, 1, 0);
        }
        // 65th entry should fail.
        assert_eq!(sys_exit_group(&mut t, 999, 1, 0), Err(Error::OutOfMemory));
    }
}
