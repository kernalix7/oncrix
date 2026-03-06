// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Process resource limits: `prlimit64(2)`, `getrlimit(2)`, `setrlimit(2)`.
//!
//! Each process carries a set of resource limits controlling CPU time, file
//! size, address space, open file descriptors, stack depth, and more.  Each
//! resource has a *soft limit* (the enforcement boundary) and a *hard limit*
//! (the ceiling the soft limit cannot exceed without privilege).
//!
//! # Operations
//!
//! | Syscall       | Handler              | Purpose                            |
//! |---------------|----------------------|------------------------------------|
//! | `getrlimit`   | [`sys_getrlimit`]    | Query soft + hard limits           |
//! | `setrlimit`   | [`sys_setrlimit`]    | Update soft + hard limits          |
//! | `prlimit64`   | [`sys_prlimit64`]    | Atomic get+set with optional PID   |
//!
//! # POSIX conformance
//!
//! - POSIX.1-2024: `getrlimit()`, `setrlimit()`
//! - Linux extension: `prlimit64()` with per-PID targeting
//! - Soft limit <= hard limit invariant enforced
//! - Unprivileged users may lower hard limits (irreversibly) but not raise them
//!
//! # References
//!
//! - POSIX.1-2024: `getrlimit()`, `setrlimit()`
//! - Linux: `include/uapi/linux/resource.h`, `kernel/sys.c`
//! - `man getrlimit(2)`, `man prlimit(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Resource IDs (POSIX + Linux)
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
pub const RLIMIT_NICE: usize = 13;
/// Maximum realtime CPU time (microseconds; Linux).
pub const RLIMIT_RTTIME: usize = 14;
/// Maximum realtime scheduling priority.
pub const RLIMIT_RTPRIO: usize = 15;

/// Total number of resource limit slots.
pub const RLIM_NLIMITS: usize = 16;

/// The "unlimited" sentinel value.
pub const RLIM_INFINITY: u64 = u64::MAX;

// ---------------------------------------------------------------------------
// ResourceLimit — named wrapper for resource index
// ---------------------------------------------------------------------------

/// A validated resource limit index.
///
/// Wraps a `usize` that has been checked to be within `0..RLIM_NLIMITS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimit(usize);

impl ResourceLimit {
    /// Create a validated resource limit index.
    ///
    /// Returns `Err(Error::InvalidArgument)` if `resource >= RLIM_NLIMITS`.
    pub fn new(resource: usize) -> Result<Self> {
        if resource >= RLIM_NLIMITS {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(resource))
    }

    /// Return the raw resource index.
    pub const fn index(self) -> usize {
        self.0
    }

    /// Return the name of the resource for diagnostic purposes.
    pub const fn name(self) -> &'static str {
        match self.0 {
            0 => "RLIMIT_CPU",
            1 => "RLIMIT_FSIZE",
            2 => "RLIMIT_DATA",
            3 => "RLIMIT_STACK",
            4 => "RLIMIT_CORE",
            5 => "RLIMIT_RSS",
            6 => "RLIMIT_NPROC",
            7 => "RLIMIT_NOFILE",
            8 => "RLIMIT_MEMLOCK",
            9 => "RLIMIT_AS",
            10 => "RLIMIT_LOCKS",
            11 => "RLIMIT_SIGPENDING",
            12 => "RLIMIT_MSGQUEUE",
            13 => "RLIMIT_NICE",
            14 => "RLIMIT_RTTIME",
            15 => "RLIMIT_RTPRIO",
            _ => "UNKNOWN",
        }
    }
}

// ---------------------------------------------------------------------------
// RlimitResource — a single soft/hard limit pair
// ---------------------------------------------------------------------------

/// A single resource limit pair matching `struct rlimit64`.
///
/// Layout is `repr(C)` for direct copy to/from user space.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rlimit64 {
    /// Soft limit (current enforcement value).
    pub rlim_cur: u64,
    /// Hard limit (ceiling; cannot be raised without privilege).
    pub rlim_max: u64,
}

impl Rlimit64 {
    /// An unlimited resource limit.
    pub const UNLIMITED: Self = Self {
        rlim_cur: RLIM_INFINITY,
        rlim_max: RLIM_INFINITY,
    };

    /// Construct a new limit with explicit soft and hard values.
    pub const fn new(soft: u64, hard: u64) -> Self {
        Self {
            rlim_cur: soft,
            rlim_max: hard,
        }
    }

    /// Return `true` if the soft limit is unlimited.
    pub const fn is_soft_unlimited(&self) -> bool {
        self.rlim_cur == RLIM_INFINITY
    }

    /// Return `true` if the hard limit is unlimited.
    pub const fn is_hard_unlimited(&self) -> bool {
        self.rlim_max == RLIM_INFINITY
    }
}

impl Default for Rlimit64 {
    fn default() -> Self {
        Self::UNLIMITED
    }
}

// ---------------------------------------------------------------------------
// validate_limit — check soft <= hard invariant
// ---------------------------------------------------------------------------

/// Validate a new resource limit pair.
///
/// Ensures the soft limit does not exceed the hard limit (unless both are
/// infinity).
///
/// # Errors
///
/// [`Error::InvalidArgument`] if `soft > hard` and neither is infinity.
pub fn validate_limit(new: &Rlimit64) -> Result<()> {
    if new.rlim_cur != RLIM_INFINITY && new.rlim_max != RLIM_INFINITY && new.rlim_cur > new.rlim_max
    {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Default limits (POSIX minimums + sensible defaults)
// ---------------------------------------------------------------------------

/// Produce the default resource limits for a new process.
///
/// Values model typical Linux defaults on a 64-bit system.
fn default_limits() -> [Rlimit64; RLIM_NLIMITS] {
    let mut lims = [Rlimit64::UNLIMITED; RLIM_NLIMITS];
    lims[RLIMIT_CPU] = Rlimit64::UNLIMITED;
    lims[RLIMIT_FSIZE] = Rlimit64::UNLIMITED;
    lims[RLIMIT_DATA] = Rlimit64::UNLIMITED;
    lims[RLIMIT_STACK] = Rlimit64::new(8 * 1024 * 1024, RLIM_INFINITY);
    lims[RLIMIT_CORE] = Rlimit64::new(0, RLIM_INFINITY);
    lims[RLIMIT_RSS] = Rlimit64::UNLIMITED;
    lims[RLIMIT_NPROC] = Rlimit64::new(4096, 4096);
    lims[RLIMIT_NOFILE] = Rlimit64::new(1024, 4096);
    lims[RLIMIT_MEMLOCK] = Rlimit64::new(64 * 1024, 64 * 1024);
    lims[RLIMIT_AS] = Rlimit64::UNLIMITED;
    lims[RLIMIT_LOCKS] = Rlimit64::UNLIMITED;
    lims[RLIMIT_SIGPENDING] = Rlimit64::new(1024, 1024);
    lims[RLIMIT_MSGQUEUE] = Rlimit64::new(819_200, 819_200);
    lims[RLIMIT_NICE] = Rlimit64::new(0, 0);
    lims[RLIMIT_RTTIME] = Rlimit64::UNLIMITED;
    lims[RLIMIT_RTPRIO] = Rlimit64::new(0, 0);
    lims
}

// ---------------------------------------------------------------------------
// ProcessLimits — per-process limit set
// ---------------------------------------------------------------------------

/// The complete resource limit set for one process.
pub struct ProcessLimits {
    limits: [Rlimit64; RLIM_NLIMITS],
    /// UID of the owning process (for privilege checks).
    pub uid: u32,
    /// PID of the owning process.
    pub pid: u32,
}

impl ProcessLimits {
    /// Create a new limit set with default values.
    pub fn new(pid: u32, uid: u32) -> Self {
        Self {
            limits: default_limits(),
            uid,
            pid,
        }
    }

    /// Return the limit for the given resource.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] if `resource >= RLIM_NLIMITS`.
    pub fn get(&self, resource: usize) -> Result<Rlimit64> {
        let r = ResourceLimit::new(resource)?;
        Ok(self.limits[r.index()])
    }

    /// Set the limit for a resource, checking privilege rules.
    ///
    /// An unprivileged process may lower the hard limit (irreversibly) and
    /// raise the soft limit up to the current hard limit.  Only privileged
    /// processes (UID 0) may raise the hard limit.
    ///
    /// # Errors
    ///
    /// * [`Error::InvalidArgument`]  — bad resource or soft > hard.
    /// * [`Error::PermissionDenied`] — unprivileged caller raising hard.
    pub fn set(&mut self, resource: usize, new_limit: Rlimit64, caller_uid: u32) -> Result<()> {
        let r = ResourceLimit::new(resource)?;
        validate_limit(&new_limit)?;

        let current = self.limits[r.index()];

        // Unprivileged checks.
        if caller_uid != 0 {
            // May not raise hard limit.
            if !new_limit.is_hard_unlimited()
                && (current.is_hard_unlimited() || new_limit.rlim_max > current.rlim_max)
            {
                return Err(Error::PermissionDenied);
            }
            // Soft must not exceed effective hard.
            let effective_hard = if new_limit.is_hard_unlimited() {
                current.rlim_max
            } else {
                new_limit.rlim_max
            };
            if !new_limit.is_soft_unlimited()
                && effective_hard != RLIM_INFINITY
                && new_limit.rlim_cur > effective_hard
            {
                return Err(Error::InvalidArgument);
            }
        }

        self.limits[r.index()] = new_limit;
        Ok(())
    }

    /// Check whether a usage value exceeds the soft limit for a resource.
    ///
    /// Returns `true` if `usage > soft_limit` (i.e., the limit is exceeded).
    pub fn is_exceeded(&self, resource: usize, usage: u64) -> bool {
        if let Ok(r) = ResourceLimit::new(resource) {
            let lim = self.limits[r.index()];
            !lim.is_soft_unlimited() && usage > lim.rlim_cur
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// LimitTable — global process limit registry
// ---------------------------------------------------------------------------

/// Maximum processes in the limit registry.
pub const LIMIT_TABLE_SIZE: usize = 64;

/// Global per-process resource limit registry.
pub struct LimitTable {
    entries: [Option<ProcessLimits>; LIMIT_TABLE_SIZE],
}

impl LimitTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; LIMIT_TABLE_SIZE],
        }
    }

    /// Register a new process.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfMemory`] if the table is full.
    pub fn register(&mut self, set: ProcessLimits) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(set);
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find an immutable limit set by PID.
    pub fn get(&self, pid: u32) -> Option<&ProcessLimits> {
        self.entries
            .iter()
            .find_map(|s| s.as_ref().filter(|e| e.pid == pid))
    }

    /// Find a mutable limit set by PID.
    pub fn get_mut(&mut self, pid: u32) -> Option<&mut ProcessLimits> {
        self.entries
            .iter_mut()
            .find_map(|s| s.as_mut().filter(|e| e.pid == pid))
    }

    /// Remove a process entry on exit.
    pub fn unregister(&mut self, pid: u32) {
        for slot in self.entries.iter_mut() {
            if slot.as_ref().is_some_and(|e| e.pid == pid) {
                *slot = None;
                return;
            }
        }
    }

    /// Inherit limits from a parent to a child process.
    ///
    /// Creates a new entry for `child_pid` with the same limits as
    /// `parent_pid`.
    ///
    /// # Errors
    ///
    /// * [`Error::NotFound`]     — parent not registered.
    /// * [`Error::OutOfMemory`]  — table full.
    pub fn inherit(&mut self, parent_pid: u32, child_pid: u32, child_uid: u32) -> Result<()> {
        let parent_limits = self.get(parent_pid).ok_or(Error::NotFound)?.limits;
        let child = ProcessLimits {
            limits: parent_limits,
            uid: child_uid,
            pid: child_pid,
        };
        self.register(child)
    }
}

impl Default for LimitTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// sys_getrlimit
// ---------------------------------------------------------------------------

/// Handler for `getrlimit(2)`.
///
/// Returns the current soft and hard limits for `resource`.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — `resource` is out of range.
pub fn sys_getrlimit(set: &ProcessLimits, resource: usize) -> Result<Rlimit64> {
    set.get(resource)
}

// ---------------------------------------------------------------------------
// sys_setrlimit
// ---------------------------------------------------------------------------

/// Handler for `setrlimit(2)`.
///
/// Updates the soft and/or hard limit for `resource`.
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — bad resource or soft > hard.
/// * [`Error::PermissionDenied`] — unprivileged caller raising hard limit.
pub fn sys_setrlimit(
    set: &mut ProcessLimits,
    resource: usize,
    new_limit: Rlimit64,
    caller_uid: u32,
) -> Result<()> {
    set.set(resource, new_limit, caller_uid)
}

// ---------------------------------------------------------------------------
// sys_prlimit64
// ---------------------------------------------------------------------------

/// Handler for `prlimit64(2)`.
///
/// Atomically gets and/or sets the resource limit for `pid`.  When
/// `pid == 0` the calling process is targeted.
///
/// # Arguments
///
/// * `table`      — Global process resource limit table.
/// * `pid`        — Target PID (0 = caller).
/// * `caller_pid` — PID of the calling process.
/// * `caller_uid` — UID of the calling process.
/// * `resource`   — Which resource (0..`RLIM_NLIMITS`).
/// * `new_limit`  — `Some(limit)` to update, `None` to query only.
///
/// # Returns
///
/// The *old* limit (before any update).
///
/// # Errors
///
/// * [`Error::NotFound`]         — target PID not found.
/// * [`Error::InvalidArgument`]  — bad resource or soft > hard.
/// * [`Error::PermissionDenied`] — caller lacks privilege.
///
/// # Linux conformance
///
/// - `prlimit64` uses `u64` for both fields (unlike 32-bit `rlimit`).
/// - A process may always call `prlimit64` on itself.
/// - Cross-process `prlimit64` requires `CAP_SYS_RESOURCE` for raising
///   hard limits; here simplified to `caller_uid == 0`.
pub fn sys_prlimit64(
    table: &mut LimitTable,
    pid: u32,
    caller_pid: u32,
    caller_uid: u32,
    resource: usize,
    new_limit: Option<Rlimit64>,
) -> Result<Rlimit64> {
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

    fn make_set(pid: u32, uid: u32) -> ProcessLimits {
        ProcessLimits::new(pid, uid)
    }

    fn make_table() -> LimitTable {
        let mut t = LimitTable::new();
        t.register(make_set(100, 500)).unwrap();
        t.register(make_set(200, 0)).unwrap();
        t
    }

    // --- ResourceLimit ---

    #[test]
    fn resource_limit_valid() {
        let r = ResourceLimit::new(RLIMIT_NOFILE).unwrap();
        assert_eq!(r.index(), RLIMIT_NOFILE);
        assert_eq!(r.name(), "RLIMIT_NOFILE");
    }

    #[test]
    fn resource_limit_out_of_range() {
        assert_eq!(
            ResourceLimit::new(RLIM_NLIMITS),
            Err(Error::InvalidArgument)
        );
    }

    // --- validate_limit ---

    #[test]
    fn validate_limit_soft_gt_hard() {
        let lim = Rlimit64::new(8192, 4096);
        assert_eq!(validate_limit(&lim), Err(Error::InvalidArgument));
    }

    #[test]
    fn validate_limit_both_infinity() {
        assert!(validate_limit(&Rlimit64::UNLIMITED).is_ok());
    }

    // --- getrlimit ---

    #[test]
    fn getrlimit_nofile_default() {
        let set = make_set(100, 500);
        let lim = sys_getrlimit(&set, RLIMIT_NOFILE).unwrap();
        assert_eq!(lim.rlim_cur, 1024);
        assert_eq!(lim.rlim_max, 4096);
    }

    #[test]
    fn getrlimit_stack_default() {
        let set = make_set(100, 500);
        let lim = sys_getrlimit(&set, RLIMIT_STACK).unwrap();
        assert_eq!(lim.rlim_cur, 8 * 1024 * 1024);
        assert_eq!(lim.rlim_max, RLIM_INFINITY);
    }

    #[test]
    fn getrlimit_invalid_resource() {
        let set = make_set(100, 500);
        assert_eq!(
            sys_getrlimit(&set, RLIM_NLIMITS),
            Err(Error::InvalidArgument)
        );
    }

    // --- setrlimit ---

    #[test]
    fn setrlimit_lower_soft() {
        let mut set = make_set(100, 500);
        sys_setrlimit(&mut set, RLIMIT_NOFILE, Rlimit64::new(512, 4096), 500).unwrap();
        assert_eq!(sys_getrlimit(&set, RLIMIT_NOFILE).unwrap().rlim_cur, 512);
    }

    #[test]
    fn setrlimit_raise_soft_within_hard() {
        let mut set = make_set(100, 500);
        sys_setrlimit(&mut set, RLIMIT_NOFILE, Rlimit64::new(2048, 4096), 500).unwrap();
        assert_eq!(sys_getrlimit(&set, RLIMIT_NOFILE).unwrap().rlim_cur, 2048);
    }

    #[test]
    fn setrlimit_unpriv_raise_hard_denied() {
        let mut set = make_set(100, 500);
        assert_eq!(
            sys_setrlimit(&mut set, RLIMIT_NOFILE, Rlimit64::new(1024, 8192), 500,),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn setrlimit_root_raise_hard() {
        let mut set = make_set(100, 0);
        sys_setrlimit(&mut set, RLIMIT_NOFILE, Rlimit64::new(1024, 65536), 0).unwrap();
        assert_eq!(sys_getrlimit(&set, RLIMIT_NOFILE).unwrap().rlim_max, 65536);
    }

    #[test]
    fn setrlimit_soft_exceeds_hard_rejected() {
        let mut set = make_set(100, 500);
        assert_eq!(
            sys_setrlimit(&mut set, RLIMIT_NOFILE, Rlimit64::new(8192, 4096), 500,),
            Err(Error::InvalidArgument)
        );
    }

    // --- prlimit64 ---

    #[test]
    fn prlimit64_query_only() {
        let mut t = make_table();
        let old = sys_prlimit64(&mut t, 100, 100, 500, RLIMIT_NOFILE, None).unwrap();
        assert_eq!(old.rlim_cur, 1024);
    }

    #[test]
    fn prlimit64_self_pid_zero() {
        let mut t = make_table();
        let old = sys_prlimit64(&mut t, 0, 100, 500, RLIMIT_NOFILE, None).unwrap();
        assert_eq!(old.rlim_cur, 1024);
    }

    #[test]
    fn prlimit64_set_and_get_old() {
        let mut t = make_table();
        let new = Rlimit64::new(512, 4096);
        let old = sys_prlimit64(&mut t, 100, 100, 500, RLIMIT_NOFILE, Some(new)).unwrap();
        assert_eq!(old.rlim_cur, 1024);
        let current = sys_prlimit64(&mut t, 100, 100, 500, RLIMIT_NOFILE, None).unwrap();
        assert_eq!(current.rlim_cur, 512);
    }

    #[test]
    fn prlimit64_cross_process_root() {
        let mut t = make_table();
        let new = Rlimit64::new(2048, 4096);
        sys_prlimit64(&mut t, 100, 200, 0, RLIMIT_NOFILE, Some(new)).unwrap();
        let current = sys_prlimit64(&mut t, 100, 100, 500, RLIMIT_NOFILE, None).unwrap();
        assert_eq!(current.rlim_cur, 2048);
    }

    #[test]
    fn prlimit64_cross_process_unpriv_denied() {
        let mut t = make_table();
        let new = Rlimit64::new(512, 4096);
        assert_eq!(
            sys_prlimit64(&mut t, 200, 100, 500, RLIMIT_NOFILE, Some(new),),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn prlimit64_nonexistent_pid() {
        let mut t = make_table();
        assert_eq!(
            sys_prlimit64(&mut t, 9999, 9999, 500, RLIMIT_NOFILE, None),
            Err(Error::NotFound)
        );
    }

    // --- ProcessLimits::is_exceeded ---

    #[test]
    fn is_exceeded_within_limit() {
        let set = make_set(100, 500);
        assert!(!set.is_exceeded(RLIMIT_NOFILE, 512));
    }

    #[test]
    fn is_exceeded_over_limit() {
        let set = make_set(100, 500);
        assert!(set.is_exceeded(RLIMIT_NOFILE, 2048));
    }

    #[test]
    fn is_exceeded_unlimited() {
        let set = make_set(100, 500);
        assert!(!set.is_exceeded(RLIMIT_CPU, u64::MAX));
    }

    // --- LimitTable::inherit ---

    #[test]
    fn inherit_copies_limits() {
        let mut t = make_table();
        t.inherit(100, 300, 500).unwrap();
        let child = t.get(300).unwrap();
        assert_eq!(child.get(RLIMIT_NOFILE).unwrap().rlim_cur, 1024);
    }

    #[test]
    fn inherit_nonexistent_parent() {
        let mut t = make_table();
        assert_eq!(t.inherit(9999, 300, 500), Err(Error::NotFound));
    }

    // --- LimitTable::unregister ---

    #[test]
    fn unregister_removes_process() {
        let mut t = make_table();
        assert!(t.get(100).is_some());
        t.unregister(100);
        assert!(t.get(100).is_none());
    }
}
