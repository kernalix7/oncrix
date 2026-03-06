// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `prlimit64(2)` syscall handler.
//!
//! Sets and/or retrieves the resource limits for an arbitrary process,
//! identified by PID.  Unlike `setrlimit(2)` / `getrlimit(2)` which operate
//! on the calling process, `prlimit64` supports targeting other processes and
//! uses the 64-bit `struct rlimit64` type.
//!
//! # Syscall signature
//!
//! ```text
//! int prlimit64(pid_t pid, int resource,
//!               const struct rlimit64 *new_limit,
//!               struct rlimit64 *old_limit);
//! ```
//!
//! # POSIX reference
//!
//! POSIX.1-2024 does not standardise `prlimit64` by that name; the standard
//! defines `setrlimit` / `getrlimit`.  Linux `prlimit64` is a superset that
//! adds PID targeting and explicit 64-bit types.
//!
//! # References
//!
//! - Linux: `kernel/sys.c` `do_prlimit()`
//! - `prlimit(2)` man page
//! - `include/uapi/linux/resource.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Resource constants
// ---------------------------------------------------------------------------

/// CPU time limit (seconds).
pub const RLIMIT_CPU: u32 = 0;
/// Maximum file size (bytes).
pub const RLIMIT_FSIZE: u32 = 1;
/// Maximum data segment (bytes).
pub const RLIMIT_DATA: u32 = 2;
/// Maximum stack size (bytes).
pub const RLIMIT_STACK: u32 = 3;
/// Maximum core dump size (bytes).
pub const RLIMIT_CORE: u32 = 4;
/// Maximum RSS (bytes, advisory).
pub const RLIMIT_RSS: u32 = 5;
/// Maximum number of processes.
pub const RLIMIT_NPROC: u32 = 6;
/// Maximum open files.
pub const RLIMIT_NOFILE: u32 = 7;
/// Maximum locked memory (bytes).
pub const RLIMIT_MEMLOCK: u32 = 8;
/// Maximum virtual address space (bytes).
pub const RLIMIT_AS: u32 = 9;
/// Maximum file locks.
pub const RLIMIT_LOCKS: u32 = 10;
/// Maximum pending signals.
pub const RLIMIT_SIGPENDING: u32 = 11;
/// Maximum POSIX MQ bytes.
pub const RLIMIT_MSGQUEUE: u32 = 12;
/// Maximum RT scheduling priority.
pub const RLIMIT_RTPRIO: u32 = 13;
/// Maximum RT scheduling time (μs).
pub const RLIMIT_RTTIME: u32 = 14;

/// Number of recognised resources.
pub const RLIM_NLIMITS: u32 = 15;

/// Sentinel meaning "no limit".
pub const RLIM64_INFINITY: u64 = u64::MAX;

/// Maximum valid PID value.
const PID_MAX: u64 = 4_194_304;

// ---------------------------------------------------------------------------
// RLimit64 — 64-bit resource limit pair
// ---------------------------------------------------------------------------

/// 64-bit resource limit pair.
///
/// Mirrors `struct rlimit64` from the Linux UAPI.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RLimit64 {
    /// Soft limit (currently enforced).
    pub rlim_cur: u64,
    /// Hard limit (ceiling for the soft limit).
    pub rlim_max: u64,
}

impl RLimit64 {
    /// Unlimited limit pair.
    pub const UNLIMITED: Self = Self {
        rlim_cur: RLIM64_INFINITY,
        rlim_max: RLIM64_INFINITY,
    };

    /// Return `true` if the soft limit exceeds the hard limit.
    pub const fn is_soft_exceeding_hard(&self) -> bool {
        self.rlim_cur != RLIM64_INFINITY
            && self.rlim_max != RLIM64_INFINITY
            && self.rlim_cur > self.rlim_max
    }
}

impl Default for RLimit64 {
    fn default() -> Self {
        Self::UNLIMITED
    }
}

// ---------------------------------------------------------------------------
// Caller credentials
// ---------------------------------------------------------------------------

/// Credentials needed by `prlimit64`.
#[derive(Debug, Clone, Copy)]
pub struct Prlimit64Cred {
    /// Calling process ID.
    pub caller_pid: u64,
    /// True if the caller has `CAP_SYS_RESOURCE`.
    pub has_sys_resource: bool,
    /// True if the caller has `CAP_SYS_ADMIN`.
    pub has_sys_admin: bool,
}

// ---------------------------------------------------------------------------
// Prlimit64Table — per-process limit store
// ---------------------------------------------------------------------------

/// Per-process 64-bit resource limit table.
pub struct Prlimit64Table {
    pid: u64,
    limits: [RLimit64; RLIM_NLIMITS as usize],
}

impl Prlimit64Table {
    /// Create a table for `pid` with all limits set to unlimited.
    pub const fn new(pid: u64) -> Self {
        Self {
            pid,
            limits: [const { RLimit64::UNLIMITED }; RLIM_NLIMITS as usize],
        }
    }

    /// Return the pid this table belongs to.
    pub const fn pid(&self) -> u64 {
        self.pid
    }

    /// Get the current limit for `resource`.
    pub fn get(&self, resource: u32) -> Result<RLimit64> {
        if resource >= RLIM_NLIMITS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.limits[resource as usize])
    }

    /// Set the limit for `resource`.
    pub fn set(&mut self, resource: u32, limit: RLimit64) -> Result<()> {
        if resource >= RLIM_NLIMITS {
            return Err(Error::InvalidArgument);
        }
        self.limits[resource as usize] = limit;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ProcessTable — collection of per-process limit tables
// ---------------------------------------------------------------------------

/// Maximum processes in the table.
const MAX_PROCS: usize = 64;

/// Global process limit registry.
pub struct ProcessLimitRegistry {
    tables: [Option<Prlimit64Table>; MAX_PROCS],
}

impl ProcessLimitRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            tables: [const { None }; MAX_PROCS],
        }
    }

    /// Return a shared reference to the limit table for `pid`.
    pub fn get(&self, pid: u64) -> Option<&Prlimit64Table> {
        self.tables
            .iter()
            .filter_map(|t| t.as_ref())
            .find(|t| t.pid == pid)
    }

    /// Return a mutable reference to the limit table for `pid`,
    /// creating a new default table if none exists.
    pub fn get_or_create_mut(&mut self, pid: u64) -> Result<&mut Prlimit64Table> {
        // Check if it already exists.
        let existing = self
            .tables
            .iter()
            .position(|t| t.as_ref().map(|t| t.pid) == Some(pid));
        if let Some(idx) = existing {
            return Ok(self.tables[idx].as_mut().unwrap());
        }

        // Insert a new table.
        let free = self
            .tables
            .iter()
            .position(|t| t.is_none())
            .ok_or(Error::OutOfMemory)?;
        self.tables[free] = Some(Prlimit64Table::new(pid));
        Ok(self.tables[free].as_mut().unwrap())
    }
}

impl Default for ProcessLimitRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Check permission for a `prlimit64` call.
///
/// Targeting another process requires either:
/// - the caller is the same process, or
/// - the caller has `CAP_SYS_RESOURCE` (or `CAP_SYS_ADMIN` for raise).
fn check_permission(target_pid: u64, cred: &Prlimit64Cred) -> Result<()> {
    if target_pid == cred.caller_pid {
        return Ok(());
    }
    if cred.has_sys_resource || cred.has_sys_admin {
        return Ok(());
    }
    Err(Error::PermissionDenied)
}

/// Validate the new limit.
fn validate_new_limit(
    new_limit: &RLimit64,
    current: &RLimit64,
    cred: &Prlimit64Cred,
) -> Result<()> {
    if new_limit.is_soft_exceeding_hard() {
        return Err(Error::InvalidArgument);
    }

    if !cred.has_sys_resource {
        // Cannot raise hard limit without privilege.
        let raises_hard = match (current.rlim_max, new_limit.rlim_max) {
            (RLIM64_INFINITY, v) => v != RLIM64_INFINITY,
            (cur, new) if new != RLIM64_INFINITY => new > cur,
            _ => false,
        };
        if raises_hard {
            return Err(Error::PermissionDenied);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// sys_prlimit64 — entry point
// ---------------------------------------------------------------------------

/// Handler for `prlimit64(2)`.
///
/// Retrieves and/or sets the resource limit for process `pid` (0 = self).
///
/// Passing `new_limit = None` is a pure get; passing `old_limit = false`
/// (the bool parameter) suppresses return of the old value.
///
/// # Arguments
///
/// * `registry`   — Process limit registry.
/// * `pid`        — Target process (0 = caller).
/// * `resource`   — Resource ID.
/// * `new_limit`  — New limit to apply (or `None` for get-only).
/// * `cred`       — Caller credentials.
///
/// # Returns
///
/// `Ok(old_limit)` — the limit that was in place before the call.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — bad resource, PID, or limit constraints.
/// * [`Error::PermissionDenied`] — not allowed to modify the target.
/// * [`Error::OutOfMemory`]      — registry full.
pub fn sys_prlimit64(
    registry: &mut ProcessLimitRegistry,
    pid: u64,
    resource: u32,
    new_limit: Option<&RLimit64>,
    cred: &Prlimit64Cred,
) -> Result<RLimit64> {
    if pid > PID_MAX {
        return Err(Error::InvalidArgument);
    }
    if resource >= RLIM_NLIMITS {
        return Err(Error::InvalidArgument);
    }

    let target_pid = if pid == 0 { cred.caller_pid } else { pid };
    check_permission(target_pid, cred)?;

    // Get current limit (or default).
    let current = registry
        .get(target_pid)
        .map(|t| t.get(resource))
        .unwrap_or(Ok(RLimit64::UNLIMITED))?;

    if let Some(nl) = new_limit {
        validate_new_limit(nl, &current, cred)?;
        let table = registry.get_or_create_mut(target_pid)?;
        table.set(resource, *nl)?;
    }

    Ok(current)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn priv_cred(caller_pid: u64) -> Prlimit64Cred {
        Prlimit64Cred {
            caller_pid,
            has_sys_resource: true,
            has_sys_admin: false,
        }
    }
    fn unpriv_cred(caller_pid: u64) -> Prlimit64Cred {
        Prlimit64Cred {
            caller_pid,
            has_sys_resource: false,
            has_sys_admin: false,
        }
    }

    #[test]
    fn get_own_defaults() {
        let mut reg = ProcessLimitRegistry::new();
        let cred = priv_cred(1);
        let lim = sys_prlimit64(&mut reg, 0, RLIMIT_NOFILE, None, &cred).unwrap();
        assert_eq!(lim, RLimit64::UNLIMITED);
    }

    #[test]
    fn set_and_get() {
        let mut reg = ProcessLimitRegistry::new();
        let cred = priv_cred(1);
        let new = RLimit64 {
            rlim_cur: 1024,
            rlim_max: 4096,
        };
        let old = sys_prlimit64(&mut reg, 0, RLIMIT_NOFILE, Some(&new), &cred).unwrap();
        assert_eq!(old, RLimit64::UNLIMITED);
        let got = sys_prlimit64(&mut reg, 0, RLIMIT_NOFILE, None, &cred).unwrap();
        assert_eq!(got, new);
    }

    #[test]
    fn cross_process_requires_cap() {
        let mut reg = ProcessLimitRegistry::new();
        let cred = unpriv_cred(1);
        assert_eq!(
            sys_prlimit64(&mut reg, 99, RLIMIT_NOFILE, None, &cred),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn cross_process_with_cap() {
        let mut reg = ProcessLimitRegistry::new();
        let cred = priv_cred(1);
        let new = RLimit64 {
            rlim_cur: 512,
            rlim_max: 1024,
        };
        sys_prlimit64(&mut reg, 99, RLIMIT_NOFILE, Some(&new), &cred).unwrap();
        let got = sys_prlimit64(&mut reg, 99, RLIMIT_NOFILE, None, &cred).unwrap();
        assert_eq!(got, new);
    }

    #[test]
    fn soft_exceeds_hard_rejected() {
        let mut reg = ProcessLimitRegistry::new();
        let cred = priv_cred(1);
        let bad = RLimit64 {
            rlim_cur: 8192,
            rlim_max: 4096,
        };
        assert_eq!(
            sys_prlimit64(&mut reg, 0, RLIMIT_NOFILE, Some(&bad), &cred),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn bad_resource_rejected() {
        let mut reg = ProcessLimitRegistry::new();
        let cred = priv_cred(1);
        assert_eq!(
            sys_prlimit64(&mut reg, 0, RLIM_NLIMITS, None, &cred),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unpriv_raise_hard_denied() {
        let mut reg = ProcessLimitRegistry::new();
        // First set a finite hard limit with privilege.
        let pcred = priv_cred(1);
        let lim = RLimit64 {
            rlim_cur: 100,
            rlim_max: 1000,
        };
        sys_prlimit64(&mut reg, 0, RLIMIT_NOFILE, Some(&lim), &pcred).unwrap();
        // Now try to raise hard limit without privilege.
        let unpriv = unpriv_cred(1);
        let raise = RLimit64 {
            rlim_cur: 100,
            rlim_max: 2000,
        };
        assert_eq!(
            sys_prlimit64(&mut reg, 0, RLIMIT_NOFILE, Some(&raise), &unpriv),
            Err(Error::PermissionDenied)
        );
    }
}
