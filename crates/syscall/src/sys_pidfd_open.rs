// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `pidfd_open(2)` — process file descriptor creation.
//!
//! A pidfd is a file descriptor that refers to a specific process instance.
//! Unlike raw PIDs, a pidfd is immune to PID reuse races: if the referenced
//! process exits, the pidfd becomes pollable but never silently refers to a
//! new process that happened to reuse the same PID.
//!
//! # Syscall signature
//!
//! ```text
//! int pidfd_open(pid_t pid, unsigned int flags);
//! ```
//!
//! # Flags
//!
//! | Flag             | Value | Effect                                         |
//! |------------------|-------|------------------------------------------------|
//! | `PIDFD_NONBLOCK` | 2048  | Set `O_NONBLOCK` on the returned descriptor.   |
//!
//! # Lifecycle
//!
//! 1. Caller supplies a PID and optional flags.
//! 2. Kernel validates the PID is positive and refers to a live process.
//! 3. A new file descriptor is allocated in the calling process's fd table.
//! 4. The fd can be passed to `poll(2)`, `waitid(2)`, `pidfd_send_signal(2)`,
//!    or `pidfd_getfd(2)`.
//! 5. When the process exits, `POLLIN | POLLHUP` becomes set.
//!
//! # POSIX context
//!
//! `pidfd_open` is a Linux extension.  POSIX.1-2024 does not standardise it.
//!
//! # Linux reference
//!
//! `kernel/pid.c` — `sys_pidfd_open`, `__pidfd_prepare`

use oncrix_lib::{Error, Result};

// Re-export the core dispatch layer constants so callers do not need to import
// both modules.
pub use crate::pidfd_open_call::{
    PIDFD_NONBLOCK, do_pidfd_open_call, sys_pidfd_open as pidfd_open_validate,
};

// ---------------------------------------------------------------------------
// Additional pidfd-open flag constants
// ---------------------------------------------------------------------------

/// All valid `pidfd_open` flags.
const FLAGS_ALL_VALID: u32 = PIDFD_NONBLOCK;

// ---------------------------------------------------------------------------
// Process state (stub)
// ---------------------------------------------------------------------------

/// Maximum number of processes tracked in the stub process table.
const MAX_PROCS: usize = 128;

/// Observed state of a process from the kernel's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcState {
    /// Process is alive and scheduled.
    Alive,
    /// Process has called `exit()` but has not yet been reaped (zombie).
    Zombie,
    /// PID slot is empty.
    Empty,
}

/// Stub entry in the process table.
#[derive(Debug, Clone, Copy)]
pub struct ProcEntry {
    /// PID of this process.
    pub pid: u32,
    /// Current lifecycle state.
    pub state: ProcState,
    /// Effective user ID.
    pub euid: u32,
}

impl ProcEntry {
    const fn empty() -> Self {
        Self {
            pid: 0,
            state: ProcState::Empty,
            euid: 0,
        }
    }
}

/// Stub process table used by `pidfd_open`.
pub struct ProcTable {
    entries: [ProcEntry; MAX_PROCS],
    count: usize,
}

impl ProcTable {
    /// Create an empty process table.
    pub const fn new() -> Self {
        Self {
            entries: [const { ProcEntry::empty() }; MAX_PROCS],
            count: 0,
        }
    }

    /// Register a process in the table.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfMemory`] if the table is full.
    /// [`Error::AlreadyExists`] if `pid` is already registered.
    pub fn insert(&mut self, pid: u32, euid: u32) -> Result<()> {
        for e in self.entries.iter() {
            if e.state != ProcState::Empty && e.pid == pid {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in self.entries.iter_mut() {
            if slot.state == ProcState::Empty {
                slot.pid = pid;
                slot.state = ProcState::Alive;
                slot.euid = euid;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find a process by PID.
    pub fn find(&self, pid: u32) -> Option<&ProcEntry> {
        self.entries
            .iter()
            .find(|e| e.state != ProcState::Empty && e.pid == pid)
    }

    /// Transition a process to zombie state.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] if the PID is not in the table or already empty.
    pub fn set_zombie(&mut self, pid: u32) -> Result<()> {
        for e in self.entries.iter_mut() {
            if e.state == ProcState::Alive && e.pid == pid {
                e.state = ProcState::Zombie;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Remove a process from the table (reap).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] if the PID is not present.
    pub fn reap(&mut self, pid: u32) -> Result<()> {
        for e in self.entries.iter_mut() {
            if e.state != ProcState::Empty && e.pid == pid {
                *e = ProcEntry::empty();
                self.count = self.count.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Return the number of active (non-empty) entries.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for ProcTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// pidfd descriptor
// ---------------------------------------------------------------------------

/// Maximum number of pidfd slots in the stub pidfd table.
const MAX_PIDFDS: usize = 64;

/// A stub pidfd descriptor — represents an open reference to a process.
#[derive(Debug, Clone, Copy)]
pub struct PidfdEntry {
    /// Whether this slot is occupied.
    pub active: bool,
    /// PID this descriptor refers to.
    pub pid: u32,
    /// Whether `O_NONBLOCK` is set.
    pub nonblock: bool,
    /// Whether the underlying process has exited (pidfd is readable).
    pub exited: bool,
    /// File descriptor number assigned to this entry.
    pub fd: i32,
}

impl PidfdEntry {
    const fn empty() -> Self {
        Self {
            active: false,
            pid: 0,
            nonblock: false,
            exited: false,
            fd: -1,
        }
    }

    /// Returns `true` if the process has exited (descriptor is readable).
    pub const fn is_readable(&self) -> bool {
        self.exited
    }
}

/// Stub pidfd table owned by a process.
pub struct PidfdTable {
    entries: [PidfdEntry; MAX_PIDFDS],
    next_fd: i32,
}

impl PidfdTable {
    /// Create an empty pidfd table.
    pub const fn new() -> Self {
        Self {
            entries: [const { PidfdEntry::empty() }; MAX_PIDFDS],
            next_fd: 10, // Start above stdio range.
        }
    }

    /// Allocate a new pidfd for the given PID.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfMemory`] if no slots are available.
    fn alloc(&mut self, pid: u32, nonblock: bool) -> Result<i32> {
        for slot in self.entries.iter_mut() {
            if !slot.active {
                let fd = self.next_fd;
                self.next_fd += 1;
                slot.active = true;
                slot.pid = pid;
                slot.nonblock = nonblock;
                slot.exited = false;
                slot.fd = fd;
                return Ok(fd);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up a pidfd entry by file descriptor number.
    pub fn find(&self, fd: i32) -> Option<&PidfdEntry> {
        self.entries.iter().find(|e| e.active && e.fd == fd)
    }

    /// Look up a pidfd entry by file descriptor number (mutable).
    pub fn find_mut(&mut self, fd: i32) -> Option<&mut PidfdEntry> {
        self.entries.iter_mut().find(|e| e.active && e.fd == fd)
    }

    /// Close a pidfd (free the slot).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] if `fd` is not an active pidfd.
    pub fn close(&mut self, fd: i32) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if slot.active && slot.fd == fd {
                *slot = PidfdEntry::empty();
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Notify all pidfds for a given PID that the process has exited.
    ///
    /// Sets `exited = true` on every active entry whose `pid` matches.
    /// Returns the number of descriptors notified.
    pub fn notify_exit(&mut self, pid: u32) -> u32 {
        let mut count = 0u32;
        for e in self.entries.iter_mut() {
            if e.active && e.pid == pid {
                e.exited = true;
                count += 1;
            }
        }
        count
    }
}

impl Default for PidfdTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// pidfd_open handler
// ---------------------------------------------------------------------------

/// Result of a successful `pidfd_open` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PidfdOpenResult {
    /// Allocated file descriptor number.
    pub fd: i32,
    /// PID the descriptor refers to.
    pub pid: u32,
    /// Whether `O_NONBLOCK` was requested.
    pub nonblock: bool,
}

/// `pidfd_open(2)` — create a process file descriptor.
///
/// Validates `pid` and `flags`, confirms the process exists in `proc_table`,
/// and allocates a new pidfd slot in `pidfd_table`.
///
/// # Arguments
///
/// * `pid`        — Process ID to open. Must be `> 0`.
/// * `flags`      — Only [`PIDFD_NONBLOCK`] is defined. Other bits are rejected.
/// * `caller_euid`— Effective UID of the caller (permission check placeholder).
/// * `proc_table` — Reference process table to look up `pid`.
/// * `pidfd_table`— Pidfd table to allocate the new descriptor in.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — `pid == 0` or unknown flags set.
/// * [`Error::NotFound`]       — No live process with `pid` in `proc_table`.
/// * [`Error::PermissionDenied`] — Caller lacks permission to observe `pid`
///   (placeholder; full PTRACE_MODE_ATTACH check not yet implemented).
/// * [`Error::OutOfMemory`]    — No free pidfd slots.
pub fn do_sys_pidfd_open(
    pid: u32,
    flags: u32,
    _caller_euid: u32,
    proc_table: &ProcTable,
    pidfd_table: &mut PidfdTable,
) -> Result<PidfdOpenResult> {
    // --- Validate arguments ---
    if pid == 0 {
        return Err(Error::InvalidArgument);
    }
    if flags & !FLAGS_ALL_VALID != 0 {
        return Err(Error::InvalidArgument);
    }

    // --- Confirm the process exists and is alive ---
    let entry = proc_table.find(pid).ok_or(Error::NotFound)?;
    if entry.state != ProcState::Alive {
        // Zombie is technically still "visible" but we reject it here to
        // model the Linux semantics: ESRCH for non-running processes.
        return Err(Error::NotFound);
    }

    // --- Allocate pidfd ---
    let nonblock = flags & PIDFD_NONBLOCK != 0;
    let fd = pidfd_table.alloc(pid, nonblock)?;

    Ok(PidfdOpenResult { fd, pid, nonblock })
}

/// Raw-argument entry point for the syscall dispatcher.
///
/// Accepts raw `u64` register values and delegates to [`do_sys_pidfd_open`].
pub fn sys_pidfd_open_raw(
    pid_raw: u64,
    flags_raw: u64,
    caller_euid: u32,
    proc_table: &ProcTable,
    pidfd_table: &mut PidfdTable,
) -> Result<PidfdOpenResult> {
    let pid = u32::try_from(pid_raw).map_err(|_| Error::InvalidArgument)?;
    let flags = u32::try_from(flags_raw).map_err(|_| Error::InvalidArgument)?;
    do_sys_pidfd_open(pid, flags, caller_euid, proc_table, pidfd_table)
}

// ---------------------------------------------------------------------------
// Poll helper
// ---------------------------------------------------------------------------

/// Poll a pidfd for readability.
///
/// Returns `true` if the process has exited (POLLIN | POLLHUP ready).
///
/// # Errors
///
/// [`Error::NotFound`] if `fd` is not an open pidfd.
pub fn pidfd_poll(pidfd_table: &PidfdTable, fd: i32) -> Result<bool> {
    let entry = pidfd_table.find(fd).ok_or(Error::NotFound)?;
    Ok(entry.is_readable())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proc_table(pids: &[(u32, u32)]) -> ProcTable {
        let mut t = ProcTable::new();
        for &(pid, euid) in pids {
            t.insert(pid, euid).unwrap();
        }
        t
    }

    #[test]
    fn open_valid_pid_succeeds() {
        let proc_t = make_proc_table(&[(1234, 1000)]);
        let mut pidfd_t = PidfdTable::new();
        let r = do_sys_pidfd_open(1234, 0, 1000, &proc_t, &mut pidfd_t).unwrap();
        assert_eq!(r.pid, 1234);
        assert!(!r.nonblock);
        assert!(r.fd >= 0);
    }

    #[test]
    fn nonblock_flag_propagated() {
        let proc_t = make_proc_table(&[(42, 0)]);
        let mut pidfd_t = PidfdTable::new();
        let r = do_sys_pidfd_open(42, PIDFD_NONBLOCK, 0, &proc_t, &mut pidfd_t).unwrap();
        assert!(r.nonblock);
        let entry = pidfd_t.find(r.fd).unwrap();
        assert!(entry.nonblock);
    }

    #[test]
    fn pid_zero_rejected() {
        let proc_t = ProcTable::new();
        let mut pidfd_t = PidfdTable::new();
        assert_eq!(
            do_sys_pidfd_open(0, 0, 0, &proc_t, &mut pidfd_t),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unknown_flags_rejected() {
        let proc_t = make_proc_table(&[(10, 0)]);
        let mut pidfd_t = PidfdTable::new();
        assert_eq!(
            do_sys_pidfd_open(10, 0xDEAD_BEEF, 0, &proc_t, &mut pidfd_t),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn nonexistent_pid_not_found() {
        let proc_t = ProcTable::new();
        let mut pidfd_t = PidfdTable::new();
        assert_eq!(
            do_sys_pidfd_open(999, 0, 0, &proc_t, &mut pidfd_t),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn zombie_pid_not_found() {
        let mut proc_t = make_proc_table(&[(77, 0)]);
        proc_t.set_zombie(77).unwrap();
        let mut pidfd_t = PidfdTable::new();
        assert_eq!(
            do_sys_pidfd_open(77, 0, 0, &proc_t, &mut pidfd_t),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn pidfd_not_readable_before_exit() {
        let proc_t = make_proc_table(&[(5, 0)]);
        let mut pidfd_t = PidfdTable::new();
        let r = do_sys_pidfd_open(5, 0, 0, &proc_t, &mut pidfd_t).unwrap();
        assert!(!pidfd_poll(&pidfd_t, r.fd).unwrap());
    }

    #[test]
    fn pidfd_readable_after_exit_notification() {
        let proc_t = make_proc_table(&[(5, 0)]);
        let mut pidfd_t = PidfdTable::new();
        let r = do_sys_pidfd_open(5, 0, 0, &proc_t, &mut pidfd_t).unwrap();
        let notified = pidfd_t.notify_exit(5);
        assert_eq!(notified, 1);
        assert!(pidfd_poll(&pidfd_t, r.fd).unwrap());
    }

    #[test]
    fn close_pidfd_removes_slot() {
        let proc_t = make_proc_table(&[(3, 0)]);
        let mut pidfd_t = PidfdTable::new();
        let r = do_sys_pidfd_open(3, 0, 0, &proc_t, &mut pidfd_t).unwrap();
        pidfd_t.close(r.fd).unwrap();
        assert!(pidfd_t.find(r.fd).is_none());
    }

    #[test]
    fn multiple_pidfds_for_same_pid() {
        let proc_t = make_proc_table(&[(99, 0)]);
        let mut pidfd_t = PidfdTable::new();
        let r1 = do_sys_pidfd_open(99, 0, 0, &proc_t, &mut pidfd_t).unwrap();
        let r2 = do_sys_pidfd_open(99, 0, 0, &proc_t, &mut pidfd_t).unwrap();
        assert_ne!(r1.fd, r2.fd);
        // Both become readable when the process exits.
        let count = pidfd_t.notify_exit(99);
        assert_eq!(count, 2);
    }

    #[test]
    fn raw_entry_point_type_check() {
        let proc_t = make_proc_table(&[(1, 0)]);
        let mut pidfd_t = PidfdTable::new();
        let r = sys_pidfd_open_raw(1, 0, 0, &proc_t, &mut pidfd_t).unwrap();
        assert_eq!(r.pid, 1);
    }

    #[test]
    fn raw_entry_overflow_rejected() {
        let proc_t = ProcTable::new();
        let mut pidfd_t = PidfdTable::new();
        let pid_overflow = u64::from(u32::MAX) + 1;
        assert_eq!(
            sys_pidfd_open_raw(pid_overflow, 0, 0, &proc_t, &mut pidfd_t),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn proc_table_duplicate_pid_rejected() {
        let mut t = ProcTable::new();
        t.insert(100, 0).unwrap();
        assert_eq!(t.insert(100, 0), Err(Error::AlreadyExists));
    }

    #[test]
    fn proc_table_reap_removes_entry() {
        let mut t = ProcTable::new();
        t.insert(200, 0).unwrap();
        t.reap(200).unwrap();
        assert!(t.find(200).is_none());
    }
}
