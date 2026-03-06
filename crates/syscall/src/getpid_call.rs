// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getpid(2)`, `getppid(2)`, `gettid(2)`, and `set_tid_address(2)`
//! syscall handlers.
//!
//! Return process/thread identity information.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `getpid()` / `getppid()`.  Key behaviours:
//! - `getpid` always succeeds and returns the caller's PID.
//! - `getppid` returns the PID of the parent; if the parent has exited and
//!   been waited for, the init process's PID (1) is returned.
//! - `gettid` returns the thread ID (Linux extension; equals PID for
//!   single-threaded processes).
//! - `set_tid_address` stores the given address for `CLONE_CHILD_CLEARTID`
//!   semantics and returns the caller's TID.
//!
//! # References
//!
//! - POSIX.1-2024: `getpid()`, `getppid()`
//! - Linux man pages: `getpid(2)`, `gettid(2)`, `set_tid_address(2)`

// ---------------------------------------------------------------------------
// Process identity
// ---------------------------------------------------------------------------

/// Minimal process identity record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessIdentity {
    /// Process ID.
    pub pid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// Thread ID.
    pub tid: u32,
    /// Clear-child-tid address (set by `set_tid_address`).
    pub clear_child_tid: u64,
}

impl ProcessIdentity {
    /// Construct a new identity for a standalone (non-threaded) process.
    pub const fn new(pid: u32, ppid: u32) -> Self {
        Self {
            pid,
            ppid,
            tid: pid,
            clear_child_tid: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `getpid(2)`.
///
/// Returns the PID of the calling process.  Always succeeds.
pub fn do_getpid(identity: &ProcessIdentity) -> u32 {
    identity.pid
}

/// Handler for `getppid(2)`.
///
/// Returns the PID of the calling process's parent.  Always succeeds.
pub fn do_getppid(identity: &ProcessIdentity) -> u32 {
    identity.ppid
}

/// Handler for `gettid(2)`.
///
/// Returns the thread ID of the calling thread.  Always succeeds.
pub fn do_gettid(identity: &ProcessIdentity) -> u32 {
    identity.tid
}

/// Handler for `set_tid_address(2)`.
///
/// Stores `tidptr` as the clear-child-tid address for this thread and
/// returns the caller's TID.
pub fn do_set_tid_address(identity: &mut ProcessIdentity, tidptr: u64) -> u32 {
    identity.clear_child_tid = tidptr;
    identity.tid
}

/// Handler for `getpgrp(2)` — returns the process group ID.
///
/// (Wrapper delegating to `setpgid_call`; here we just return a
/// pre-populated PGID for simplicity.)
pub fn do_getpgrp_simple(pgid: u32) -> u32 {
    pgid
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> ProcessIdentity {
        ProcessIdentity::new(42, 1)
    }

    #[test]
    fn getpid_returns_pid() {
        assert_eq!(do_getpid(&identity()), 42);
    }

    #[test]
    fn getppid_returns_ppid() {
        assert_eq!(do_getppid(&identity()), 1);
    }

    #[test]
    fn gettid_equals_pid_single_threaded() {
        assert_eq!(do_gettid(&identity()), 42);
    }

    #[test]
    fn set_tid_address_stores_and_returns_tid() {
        let mut id = identity();
        let tid = do_set_tid_address(&mut id, 0xDEAD_BEEF);
        assert_eq!(tid, 42);
        assert_eq!(id.clear_child_tid, 0xDEAD_BEEF);
    }

    #[test]
    fn getpgrp_simple() {
        assert_eq!(do_getpgrp_simple(10), 10);
    }
}
