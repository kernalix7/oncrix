// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getrlimit(2)`, `setrlimit(2)`, and `prlimit64(2)` syscall handlers.
//!
//! Resource limits constrain the amount of a resource (CPU time, open files,
//! stack size, …) that a process or user may consume.  Each resource has a
//! *soft limit* (the current enforcement value) and a *hard limit* (the
//! maximum value the soft limit may be raised to without privileges).
//!
//! # Operations
//!
//! | Syscall        | Handler               | Purpose                              |
//! |----------------|-----------------------|--------------------------------------|
//! | `getrlimit`    | [`do_getrlimit`]      | Query soft + hard limits             |
//! | `setrlimit`    | [`do_setrlimit`]      | Update soft + hard limits            |
//! | `prlimit64`    | [`do_prlimit64`]      | get+set with optional PID target     |
//!
//! # References
//!
//! - POSIX.1-2024: `getrlimit()`, `setrlimit()`
//! - Linux: `include/uapi/linux/resource.h`, `kernel/sys.c`
//! - `man getrlimit(2)`, `man prlimit(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Resource IDs
// ---------------------------------------------------------------------------

/// CPU time limit (seconds).
pub const RLIMIT_CPU: usize = 0;
/// Maximum file size (bytes).
pub const RLIMIT_FSIZE: usize = 1;
/// Maximum size of data segment (bytes).
pub const RLIMIT_DATA: usize = 2;
/// Maximum stack size (bytes).
pub const RLIMIT_STACK: usize = 3;
/// Maximum core file size (bytes).
pub const RLIMIT_CORE: usize = 4;
/// Maximum resident set size (bytes; advisory).
pub const RLIMIT_RSS: usize = 5;
/// Maximum number of processes (threads) for the user.
pub const RLIMIT_NPROC: usize = 6;
/// Maximum number of open file descriptors.
pub const RLIMIT_NOFILE: usize = 7;
/// Maximum size of locked memory (bytes).
pub const RLIMIT_MEMLOCK: usize = 8;
/// Maximum size of virtual memory (bytes).
pub const RLIMIT_AS: usize = 9;
/// Maximum number of file locks.
pub const RLIMIT_LOCKS: usize = 10;
/// Maximum number of pending signals.
pub const RLIMIT_SIGPENDING: usize = 11;
/// Maximum size of POSIX message queues (bytes).
pub const RLIMIT_MSGQUEUE: usize = 12;
/// Maximum scheduling priority (realtime).
pub const RLIMIT_RTPRIO: usize = 13;
/// Maximum realtime CPU time (microseconds; Linux).
pub const RLIMIT_RTTIME: usize = 14;

/// Total number of resource limit slots.
pub const RLIM_NLIMITS: usize = 15;

/// The "unlimited" sentinel value.
pub const RLIM_INFINITY: u64 = u64::MAX;

// ---------------------------------------------------------------------------
// RLimit — a single resource limit pair
// ---------------------------------------------------------------------------

/// A single resource limit, consisting of a soft and a hard limit.
///
/// Mirrors `struct rlimit64` from the Linux UAPI.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RLimit {
    /// Soft limit — the current enforcement value.
    pub soft: u64,
    /// Hard limit — ceiling the soft limit cannot exceed (without privilege).
    pub hard: u64,
}

impl RLimit {
    /// An unlimited resource limit (both soft and hard = [`RLIM_INFINITY`]).
    pub const UNLIMITED: Self = Self {
        soft: RLIM_INFINITY,
        hard: RLIM_INFINITY,
    };

    /// Construct a new limit with explicit soft and hard values.
    pub const fn new(soft: u64, hard: u64) -> Self {
        Self { soft, hard }
    }

    /// Return `true` if the soft limit is unlimited.
    pub const fn soft_unlimited(&self) -> bool {
        self.soft == RLIM_INFINITY
    }

    /// Return `true` if the hard limit is unlimited.
    pub const fn hard_unlimited(&self) -> bool {
        self.hard == RLIM_INFINITY
    }
}

impl Default for RLimit {
    fn default() -> Self {
        Self::UNLIMITED
    }
}

// ---------------------------------------------------------------------------
// Default limits (POSIX minimums + sensible defaults)
// ---------------------------------------------------------------------------

/// Produce the default resource limits for a new process.
///
/// Values are modelled after typical Linux defaults on a 64-bit system.
pub fn default_limits() -> [RLimit; RLIM_NLIMITS] {
    let mut lims = [RLimit::UNLIMITED; RLIM_NLIMITS];
    lims[RLIMIT_CPU] = RLimit::UNLIMITED;
    lims[RLIMIT_FSIZE] = RLimit::UNLIMITED;
    lims[RLIMIT_DATA] = RLimit::UNLIMITED;
    lims[RLIMIT_STACK] = RLimit::new(8 * 1024 * 1024, RLIM_INFINITY); // 8 MiB soft
    lims[RLIMIT_CORE] = RLimit::new(0, RLIM_INFINITY); // no core by default
    lims[RLIMIT_RSS] = RLimit::UNLIMITED;
    lims[RLIMIT_NPROC] = RLimit::new(4096, 4096);
    lims[RLIMIT_NOFILE] = RLimit::new(1024, 4096);
    lims[RLIMIT_MEMLOCK] = RLimit::new(64 * 1024, 64 * 1024); // 64 KiB
    lims[RLIMIT_AS] = RLimit::UNLIMITED;
    lims[RLIMIT_LOCKS] = RLimit::UNLIMITED;
    lims[RLIMIT_SIGPENDING] = RLimit::new(1024, 1024);
    lims[RLIMIT_MSGQUEUE] = RLimit::new(819200, 819200);
    lims[RLIMIT_RTPRIO] = RLimit::new(0, 0);
    lims[RLIMIT_RTTIME] = RLimit::UNLIMITED;
    lims
}

// ---------------------------------------------------------------------------
// RLimitSet — per-process resource limit table
// ---------------------------------------------------------------------------

/// The complete resource limit set for one process.
pub struct RLimitSet {
    limits: [RLimit; RLIM_NLIMITS],
    /// UID of the owning process (for privilege checks in `prlimit64`).
    pub uid: u32,
    /// PID of the owning process.
    pub pid: u32,
}

impl RLimitSet {
    /// Create a new limit set with default values.
    pub fn new(pid: u32, uid: u32) -> Self {
        Self {
            limits: default_limits(),
            uid,
            pid,
        }
    }

    /// Return the limit for `resource`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] if `resource >= RLIM_NLIMITS`.
    pub fn get(&self, resource: usize) -> Result<RLimit> {
        if resource >= RLIM_NLIMITS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.limits[resource])
    }

    /// Set the limit for `resource`, validating privilege rules.
    ///
    /// # Arguments
    ///
    /// * `resource`    — Which resource to update.
    /// * `new_limit`   — New limit pair.
    /// * `caller_uid`  — UID of the calling process.
    ///
    /// # Errors
    ///
    /// * [`Error::InvalidArgument`]  — Invalid resource index, or soft > hard.
    /// * [`Error::PermissionDenied`] — Unprivileged caller trying to raise hard limit.
    ///
    /// # POSIX conformance
    ///
    /// An unprivileged process may lower the hard limit (irreversibly) and may
    /// raise the soft limit up to the current hard limit.  Only privileged
    /// processes may raise the hard limit.
    pub fn set(&mut self, resource: usize, new_limit: RLimit, caller_uid: u32) -> Result<()> {
        if resource >= RLIM_NLIMITS {
            return Err(Error::InvalidArgument);
        }
        // Soft limit must not exceed hard limit (unless hard is infinity).
        if new_limit.soft != RLIM_INFINITY
            && new_limit.hard != RLIM_INFINITY
            && new_limit.soft > new_limit.hard
        {
            return Err(Error::InvalidArgument);
        }

        let current = self.limits[resource];

        if caller_uid != 0 {
            // Unprivileged: may not raise hard limit.
            if new_limit.hard != RLIM_INFINITY
                && (current.hard == RLIM_INFINITY || new_limit.hard > current.hard)
            {
                return Err(Error::PermissionDenied);
            }
            // Soft must not exceed hard.
            let effective_hard = if new_limit.hard == RLIM_INFINITY {
                // Keeping hard at current value when new hard is infinity means
                // caller left it at current — safe.
                current.hard
            } else {
                new_limit.hard
            };
            if new_limit.soft != RLIM_INFINITY
                && effective_hard != RLIM_INFINITY
                && new_limit.soft > effective_hard
            {
                return Err(Error::InvalidArgument);
            }
        }

        self.limits[resource] = new_limit;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Process table stub for prlimit64
// ---------------------------------------------------------------------------

/// Maximum processes in the prlimit64 stub registry.
pub const RLIMIT_PROC_TABLE_SIZE: usize = 64;

/// Global per-process resource limit registry.
pub struct RLimitProcTable {
    entries: [Option<RLimitSet>; RLIMIT_PROC_TABLE_SIZE],
}

impl RLimitProcTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; RLIMIT_PROC_TABLE_SIZE],
        }
    }

    /// Register a new process.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfMemory`] if the table is full.
    pub fn register(&mut self, set: RLimitSet) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(set);
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find immutable limit set by PID.
    pub fn get(&self, pid: u32) -> Option<&RLimitSet> {
        self.entries
            .iter()
            .find_map(|s| s.as_ref().filter(|e| e.pid == pid))
    }

    /// Find mutable limit set by PID.
    pub fn get_mut(&mut self, pid: u32) -> Option<&mut RLimitSet> {
        self.entries
            .iter_mut()
            .find_map(|s| s.as_mut().filter(|e| e.pid == pid))
    }

    /// Remove a process entry on exit.
    pub fn unregister(&mut self, pid: u32) {
        for slot in self.entries.iter_mut() {
            if slot.as_ref().map(|e| e.pid == pid).unwrap_or(false) {
                *slot = None;
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// do_getrlimit
// ---------------------------------------------------------------------------

/// Handler for `getrlimit(2)`.
///
/// Returns the current soft and hard limits for `resource`.
///
/// # Arguments
///
/// * `set`      — The process's resource limit set.
/// * `resource` — Which limit to query (0–14).
///
/// # Returns
///
/// The current [`RLimit`] for the resource.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — `resource` is out of range.
pub fn do_getrlimit(set: &RLimitSet, resource: usize) -> Result<RLimit> {
    set.get(resource)
}

// ---------------------------------------------------------------------------
// do_setrlimit
// ---------------------------------------------------------------------------

/// Handler for `setrlimit(2)`.
///
/// Updates the soft and/or hard limit for `resource`.
///
/// # Arguments
///
/// * `set`        — The process's resource limit set.
/// * `resource`   — Which limit to update (0–14).
/// * `new_limit`  — New soft/hard pair.
/// * `caller_uid` — UID of the calling process.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — Bad resource index or soft > hard.
/// * [`Error::PermissionDenied`] — Unprivileged caller raising hard limit.
pub fn do_setrlimit(
    set: &mut RLimitSet,
    resource: usize,
    new_limit: RLimit,
    caller_uid: u32,
) -> Result<()> {
    set.set(resource, new_limit, caller_uid)
}

// ---------------------------------------------------------------------------
// do_prlimit64
// ---------------------------------------------------------------------------

/// Handler for `prlimit64(2)`.
///
/// Atomically gets and/or sets the resource limit for `pid`.  When `pid == 0`
/// the calling process is targeted.
///
/// # Arguments
///
/// * `table`      — Global process resource limit table.
/// * `pid`        — Target PID (0 = caller).
/// * `caller_pid` — PID of the calling process.
/// * `caller_uid` — UID of the calling process.
/// * `resource`   — Which resource (0–14).
/// * `new_limit`  — `Some(limit)` to update, `None` to query only.
///
/// # Returns
///
/// The *old* limit (before any update).
///
/// # Errors
///
/// * [`Error::NotFound`]         — Target PID not found.
/// * [`Error::InvalidArgument`]  — Bad resource index or soft > hard.
/// * [`Error::PermissionDenied`] — Caller lacks privilege to modify target.
///
/// # Linux conformance
///
/// - `prlimit64` uses `u64` for both fields (unlike 32-bit `rlimit`).
/// - A process may always call `prlimit64` on itself.
/// - Cross-process `prlimit64` requires `CAP_SYS_RESOURCE` for raising hard
///   limits; here simplified to `caller_uid == 0`.
pub fn do_prlimit64(
    table: &mut RLimitProcTable,
    pid: u32,
    caller_pid: u32,
    caller_uid: u32,
    resource: usize,
    new_limit: Option<RLimit>,
) -> Result<RLimit> {
    let target_pid = if pid == 0 { caller_pid } else { pid };
    let cross_process = target_pid != caller_pid;

    // Cross-process modification requires root.
    if cross_process && new_limit.is_some() && caller_uid != 0 {
        return Err(Error::PermissionDenied);
    }

    let set = table.get_mut(target_pid).ok_or(Error::NotFound)?;
    let old = set.get(resource)?;

    if let Some(lim) = new_limit {
        set.set(resource, lim, caller_uid)?;
    }

    Ok(old)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_set(pid: u32, uid: u32) -> RLimitSet {
        RLimitSet::new(pid, uid)
    }

    // --- getrlimit ---

    #[test]
    fn getrlimit_nofile_default() {
        let set = make_set(100, 500);
        let lim = do_getrlimit(&set, RLIMIT_NOFILE).unwrap();
        assert_eq!(lim.soft, 1024);
        assert_eq!(lim.hard, 4096);
    }

    #[test]
    fn getrlimit_invalid_resource() {
        let set = make_set(100, 500);
        assert_eq!(
            do_getrlimit(&set, RLIM_NLIMITS),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn getrlimit_stack_default() {
        let set = make_set(100, 500);
        let lim = do_getrlimit(&set, RLIMIT_STACK).unwrap();
        assert_eq!(lim.soft, 8 * 1024 * 1024);
        assert_eq!(lim.hard, RLIM_INFINITY);
    }

    // --- setrlimit ---

    #[test]
    fn setrlimit_lower_soft() {
        let mut set = make_set(100, 500);
        let new = RLimit::new(512, 4096);
        do_setrlimit(&mut set, RLIMIT_NOFILE, new, 500).unwrap();
        assert_eq!(do_getrlimit(&set, RLIMIT_NOFILE).unwrap().soft, 512);
    }

    #[test]
    fn setrlimit_raise_soft_within_hard() {
        let mut set = make_set(100, 500);
        // hard is 4096, raise soft from 1024 to 2048
        let new = RLimit::new(2048, 4096);
        do_setrlimit(&mut set, RLIMIT_NOFILE, new, 500).unwrap();
        assert_eq!(do_getrlimit(&set, RLIMIT_NOFILE).unwrap().soft, 2048);
    }

    #[test]
    fn setrlimit_unpriv_raise_hard_denied() {
        let mut set = make_set(100, 500);
        // hard is 4096, try to raise to 8192
        let new = RLimit::new(1024, 8192);
        assert_eq!(
            do_setrlimit(&mut set, RLIMIT_NOFILE, new, 500),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn setrlimit_root_raise_hard() {
        let mut set = make_set(100, 0);
        let new = RLimit::new(1024, 65536);
        do_setrlimit(&mut set, RLIMIT_NOFILE, new, 0).unwrap();
        assert_eq!(do_getrlimit(&set, RLIMIT_NOFILE).unwrap().hard, 65536);
    }

    #[test]
    fn setrlimit_soft_exceeds_hard_rejected() {
        let mut set = make_set(100, 500);
        let new = RLimit::new(8192, 4096); // soft > hard
        assert_eq!(
            do_setrlimit(&mut set, RLIMIT_NOFILE, new, 500),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn setrlimit_unpriv_lower_hard() {
        let mut set = make_set(100, 500);
        // Lower hard from 4096 to 2048 (allowed for unprivileged)
        let new = RLimit::new(512, 2048);
        do_setrlimit(&mut set, RLIMIT_NOFILE, new, 500).unwrap();
        assert_eq!(do_getrlimit(&set, RLIMIT_NOFILE).unwrap().hard, 2048);
    }

    // --- prlimit64 ---

    fn make_table() -> RLimitProcTable {
        let mut t = RLimitProcTable::new();
        t.register(make_set(100, 500)).unwrap();
        t.register(make_set(200, 0)).unwrap(); // root process
        t
    }

    #[test]
    fn prlimit64_query_only() {
        let mut t = make_table();
        let old = do_prlimit64(&mut t, 100, 100, 500, RLIMIT_NOFILE, None).unwrap();
        assert_eq!(old.soft, 1024);
    }

    #[test]
    fn prlimit64_self_pid_zero() {
        let mut t = make_table();
        let old = do_prlimit64(&mut t, 0, 100, 500, RLIMIT_NOFILE, None).unwrap();
        assert_eq!(old.soft, 1024);
    }

    #[test]
    fn prlimit64_set_and_get_old() {
        let mut t = make_table();
        let new = RLimit::new(512, 4096);
        let old = do_prlimit64(&mut t, 100, 100, 500, RLIMIT_NOFILE, Some(new)).unwrap();
        assert_eq!(old.soft, 1024); // old value returned
        let current = do_prlimit64(&mut t, 100, 100, 500, RLIMIT_NOFILE, None).unwrap();
        assert_eq!(current.soft, 512);
    }

    #[test]
    fn prlimit64_cross_process_root() {
        let mut t = make_table();
        let new = RLimit::new(2048, 4096);
        // Root process (pid 200, uid 0) modifying pid 100
        do_prlimit64(&mut t, 100, 200, 0, RLIMIT_NOFILE, Some(new)).unwrap();
        let current = do_prlimit64(&mut t, 100, 100, 500, RLIMIT_NOFILE, None).unwrap();
        assert_eq!(current.soft, 2048);
    }

    #[test]
    fn prlimit64_cross_process_unpriv_denied() {
        let mut t = make_table();
        let new = RLimit::new(512, 4096);
        // uid 500 trying to modify another process
        assert_eq!(
            do_prlimit64(&mut t, 200, 100, 500, RLIMIT_NOFILE, Some(new)),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn prlimit64_nonexistent_pid() {
        let mut t = make_table();
        assert_eq!(
            do_prlimit64(&mut t, 9999, 9999, 500, RLIMIT_NOFILE, None),
            Err(Error::NotFound)
        );
    }

    // --- RLimitProcTable ---

    #[test]
    fn proc_table_register_unregister() {
        let mut t = RLimitProcTable::new();
        t.register(make_set(1, 0)).unwrap();
        assert!(t.get(1).is_some());
        t.unregister(1);
        assert!(t.get(1).is_none());
    }
}
