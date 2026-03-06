// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `prlimit64(2)` syscall handler — get/set resource limits for any process.
//!
//! `prlimit64` is the 64-bit, PID-targeted superset of `getrlimit`/`setrlimit`.
//! It can operate on the calling process (PID 0) or any other process, subject
//! to permission checks.
//!
//! # Syscall signature
//!
//! ```text
//! int prlimit64(pid_t pid, int resource,
//!               const struct rlimit64 *new_limit,
//!               struct rlimit64 *old_limit);
//! ```
//!
//! # Permission model
//!
//! - Targeting `pid == 0` (self) is always allowed.
//! - Targeting another process requires the same UID/GID **or** `CAP_SYS_RESOURCE`.
//! - Raising the hard limit always requires `CAP_SYS_RESOURCE`.
//!
//! # Resource clamping
//!
//! Some resources have kernel-enforced maximums.  Setting a hard limit above
//! the clamp silently clamps to the maximum (with `CAP_SYS_RESOURCE` the clamp
//! is bypassed).
//!
//! # POSIX reference
//!
//! POSIX.1-2024 standardises `getrlimit`/`setrlimit`.  `prlimit64` is a Linux
//! extension adding PID targeting and explicit 64-bit types.
//!
//! # Linux reference
//!
//! `kernel/sys.c` — `do_prlimit()`, `SYSCALL_DEFINE4(prlimit64, ...)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Resource identifiers
// ---------------------------------------------------------------------------

/// CPU time in seconds.
pub const RLIMIT_CPU: u32 = 0;
/// Maximum file size in bytes.
pub const RLIMIT_FSIZE: u32 = 1;
/// Maximum data segment size in bytes.
pub const RLIMIT_DATA: u32 = 2;
/// Maximum stack size in bytes.
pub const RLIMIT_STACK: u32 = 3;
/// Maximum core dump size in bytes.
pub const RLIMIT_CORE: u32 = 4;
/// Maximum RSS in bytes (advisory).
pub const RLIMIT_RSS: u32 = 5;
/// Maximum number of processes for the user.
pub const RLIMIT_NPROC: u32 = 6;
/// Maximum number of open files.
pub const RLIMIT_NOFILE: u32 = 7;
/// Maximum locked memory in bytes.
pub const RLIMIT_MEMLOCK: u32 = 8;
/// Maximum virtual address space in bytes.
pub const RLIMIT_AS: u32 = 9;
/// Maximum file locks.
pub const RLIMIT_LOCKS: u32 = 10;
/// Maximum pending signals.
pub const RLIMIT_SIGPENDING: u32 = 11;
/// Maximum POSIX message queue bytes.
pub const RLIMIT_MSGQUEUE: u32 = 12;
/// Maximum real-time scheduling priority.
pub const RLIMIT_RTPRIO: u32 = 13;
/// Maximum real-time CPU time (microseconds, 0 = unlimited).
pub const RLIMIT_RTTIME: u32 = 14;

/// Number of defined resources.
pub const RLIM_NLIMITS: u32 = 15;

/// Sentinel indicating no limit.
pub const RLIM64_INFINITY: u64 = u64::MAX;

// ---------------------------------------------------------------------------
// Per-resource kernel maximums (clamp values)
// ---------------------------------------------------------------------------

/// Kernel-enforced maximum for `RLIMIT_NOFILE`.
const RLIMIT_NOFILE_MAX: u64 = 1_048_576;
/// Kernel-enforced maximum for `RLIMIT_NPROC`.
const RLIMIT_NPROC_MAX: u64 = 4_194_304;
/// Kernel-enforced maximum for `RLIMIT_SIGPENDING`.
const RLIMIT_SIGPENDING_MAX: u64 = 65_536;
/// Kernel-enforced maximum for `RLIMIT_MSGQUEUE`.
const RLIMIT_MSGQUEUE_MAX: u64 = 819_200;

// ---------------------------------------------------------------------------
// RLimit64 — 64-bit limit pair
// ---------------------------------------------------------------------------

/// A 64-bit resource limit pair (`struct rlimit64`).
///
/// `rlim_cur` is the soft limit currently enforced.
/// `rlim_max` is the hard limit that unprivileged processes cannot exceed.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RLimit64 {
    /// Soft limit (currently enforced ceiling).
    pub rlim_cur: u64,
    /// Hard limit (maximum settable soft limit for unprivileged users).
    pub rlim_max: u64,
}

impl RLimit64 {
    /// Unlimited (both soft and hard set to `RLIM64_INFINITY`).
    pub const UNLIMITED: Self = Self {
        rlim_cur: RLIM64_INFINITY,
        rlim_max: RLIM64_INFINITY,
    };

    /// Return `true` when the soft limit exceeds the hard limit (invalid).
    pub const fn soft_exceeds_hard(&self) -> bool {
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
// PrlimitCred — caller credentials
// ---------------------------------------------------------------------------

/// Credentials provided to the `prlimit64` handler.
#[derive(Debug, Clone, Copy)]
pub struct PrlimitCred {
    /// UID of the calling process.
    pub uid: u32,
    /// UID of the target process (used for same-user check).
    pub target_uid: u32,
    /// `true` when the caller holds `CAP_SYS_RESOURCE`.
    pub cap_sys_resource: bool,
}

impl PrlimitCred {
    /// Return `true` when the caller is permitted to set limits on the target.
    pub fn may_set(&self) -> bool {
        self.uid == self.target_uid || self.cap_sys_resource
    }

    /// Return `true` when the caller may raise the hard limit.
    pub const fn may_raise_hard(&self) -> bool {
        self.cap_sys_resource
    }
}

// ---------------------------------------------------------------------------
// Per-resource clamping
// ---------------------------------------------------------------------------

/// Clamp a new limit against the per-resource kernel maximum.
///
/// When the caller has `CAP_SYS_RESOURCE` clamping is skipped.
fn clamp_limit(resource: u32, limit: RLimit64, privileged: bool) -> RLimit64 {
    if privileged {
        return limit;
    }
    let max = match resource {
        RLIMIT_NOFILE => RLIMIT_NOFILE_MAX,
        RLIMIT_NPROC => RLIMIT_NPROC_MAX,
        RLIMIT_SIGPENDING => RLIMIT_SIGPENDING_MAX,
        RLIMIT_MSGQUEUE => RLIMIT_MSGQUEUE_MAX,
        _ => RLIM64_INFINITY,
    };
    if max == RLIM64_INFINITY {
        return limit;
    }
    let cur = limit.rlim_cur.min(max);
    let hard = limit.rlim_max.min(max);
    RLimit64 {
        rlim_cur: cur,
        rlim_max: hard,
    }
}

// ---------------------------------------------------------------------------
// ProcessLimitTable — per-process limit storage
// ---------------------------------------------------------------------------

/// Per-process resource limit table.
pub struct ProcessLimitTable {
    /// PID this table belongs to.
    pub pid: u64,
    limits: [RLimit64; RLIM_NLIMITS as usize],
}

impl ProcessLimitTable {
    /// Create a table with all limits set to `UNLIMITED`.
    pub const fn new(pid: u64) -> Self {
        Self {
            pid,
            limits: [const { RLimit64::UNLIMITED }; RLIM_NLIMITS as usize],
        }
    }

    /// Get the limit for `resource`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] — `resource >= RLIM_NLIMITS`.
    pub fn get(&self, resource: u32) -> Result<RLimit64> {
        if resource >= RLIM_NLIMITS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.limits[resource as usize])
    }

    /// Set the limit for `resource`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] — `resource >= RLIM_NLIMITS`.
    pub fn set(&mut self, resource: u32, limit: RLimit64) -> Result<()> {
        if resource >= RLIM_NLIMITS {
            return Err(Error::InvalidArgument);
        }
        self.limits[resource as usize] = limit;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ProcessLimitRegistry — table of per-process tables
// ---------------------------------------------------------------------------

/// Maximum tracked processes.
const MAX_TRACKED: usize = 64;

/// Registry mapping PIDs to per-process limit tables.
pub struct ProcessLimitRegistry {
    tables: [Option<ProcessLimitTable>; MAX_TRACKED],
}

impl ProcessLimitRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            tables: [const { None }; MAX_TRACKED],
        }
    }

    /// Find a shared reference to the table for `pid`.
    pub fn get(&self, pid: u64) -> Option<&ProcessLimitTable> {
        self.tables
            .iter()
            .filter_map(|t| t.as_ref())
            .find(|t| t.pid == pid)
    }

    /// Find or create a mutable reference to the table for `pid`.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfMemory`] — registry is full.
    pub fn get_or_create(&mut self, pid: u64) -> Result<&mut ProcessLimitTable> {
        // Check for existing entry.
        let pos = self
            .tables
            .iter()
            .position(|t| t.as_ref().map(|t| t.pid) == Some(pid));
        if let Some(idx) = pos {
            return Ok(self.tables[idx].as_mut().unwrap());
        }
        // Allocate new slot.
        let free = self
            .tables
            .iter()
            .position(|t| t.is_none())
            .ok_or(Error::OutOfMemory)?;
        self.tables[free] = Some(ProcessLimitTable::new(pid));
        Ok(self.tables[free].as_mut().unwrap())
    }
}

impl Default for ProcessLimitRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// do_sys_prlimit — primary handler
// ---------------------------------------------------------------------------

/// `prlimit64(2)` syscall handler.
///
/// Retrieves and optionally sets resource limits for the process identified
/// by `pid` (0 = calling process, resolved via `cred.uid`).
///
/// # Arguments
///
/// * `registry`   — Per-process limit registry.
/// * `pid`        — Target PID (0 = self).
/// * `resource`   — Resource identifier (one of the `RLIMIT_*` constants).
/// * `new_limit`  — New limit to apply, or `None` for a get-only call.
/// * `cred`       — Caller credentials for permission checks.
///
/// # Returns
///
/// `Ok(old_limit)` — the previous limit for the resource.
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — bad resource or limit (soft > hard).
/// * [`Error::PermissionDenied`] — caller may not modify the target process.
/// * [`Error::OutOfMemory`]      — registry full.
pub fn do_sys_prlimit(
    registry: &mut ProcessLimitRegistry,
    pid: u64,
    resource: u32,
    new_limit: Option<RLimit64>,
    cred: &PrlimitCred,
) -> Result<RLimit64> {
    if resource >= RLIM_NLIMITS {
        return Err(Error::InvalidArgument);
    }

    // Resolve the effective PID.
    let effective_pid = if pid == 0 { cred.uid as u64 } else { pid };

    // Get the current limit (default UNLIMITED if not yet tracked).
    let current = registry
        .get(effective_pid)
        .map(|t| t.get(resource))
        .unwrap_or(Ok(RLimit64::UNLIMITED))?;

    if let Some(nl) = new_limit {
        if nl.soft_exceeds_hard() {
            return Err(Error::InvalidArgument);
        }

        // Permission: must be allowed to set limits on the target.
        if !cred.may_set() {
            return Err(Error::PermissionDenied);
        }

        // Privilege: raising the hard limit requires CAP_SYS_RESOURCE.
        if !cred.may_raise_hard() {
            let raises = match (current.rlim_max, nl.rlim_max) {
                (RLIM64_INFINITY, v) => v != RLIM64_INFINITY,
                (cur, new) if new != RLIM64_INFINITY => new > cur,
                _ => false,
            };
            if raises {
                return Err(Error::PermissionDenied);
            }
        }

        // Apply per-resource clamping.
        let clamped = clamp_limit(resource, nl, cred.cap_sys_resource);
        let table = registry.get_or_create(effective_pid)?;
        table.set(resource, clamped)?;
    }

    Ok(current)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn priv_cred() -> PrlimitCred {
        PrlimitCred {
            uid: 1000,
            target_uid: 1000,
            cap_sys_resource: true,
        }
    }

    fn unpriv_cred() -> PrlimitCred {
        PrlimitCred {
            uid: 1000,
            target_uid: 1000,
            cap_sys_resource: false,
        }
    }

    fn cross_process_cred() -> PrlimitCred {
        PrlimitCred {
            uid: 1000,
            target_uid: 2000,
            cap_sys_resource: false,
        }
    }

    #[test]
    fn get_default_unlimited() {
        let mut reg = ProcessLimitRegistry::new();
        let lim = do_sys_prlimit(&mut reg, 0, RLIMIT_NOFILE, None, &priv_cred()).unwrap();
        assert_eq!(lim, RLimit64::UNLIMITED);
    }

    #[test]
    fn set_and_retrieve() {
        let mut reg = ProcessLimitRegistry::new();
        let new = RLimit64 {
            rlim_cur: 1024,
            rlim_max: 4096,
        };
        let old = do_sys_prlimit(&mut reg, 0, RLIMIT_NOFILE, Some(new), &priv_cred()).unwrap();
        assert_eq!(old, RLimit64::UNLIMITED);
        let got = do_sys_prlimit(&mut reg, 0, RLIMIT_NOFILE, None, &priv_cred()).unwrap();
        assert_eq!(got, new);
    }

    #[test]
    fn soft_exceeds_hard_rejected() {
        let mut reg = ProcessLimitRegistry::new();
        let bad = RLimit64 {
            rlim_cur: 8192,
            rlim_max: 4096,
        };
        assert_eq!(
            do_sys_prlimit(&mut reg, 0, RLIMIT_NOFILE, Some(bad), &priv_cred()),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn cross_process_without_cap_denied() {
        let mut reg = ProcessLimitRegistry::new();
        assert_eq!(
            do_sys_prlimit(&mut reg, 999, RLIMIT_NOFILE, None, &cross_process_cred()),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn raise_hard_limit_unpriv_denied() {
        let mut reg = ProcessLimitRegistry::new();
        // Set a finite hard limit with privilege.
        let initial = RLimit64 {
            rlim_cur: 100,
            rlim_max: 1000,
        };
        do_sys_prlimit(&mut reg, 0, RLIMIT_NOFILE, Some(initial), &priv_cred()).unwrap();
        // Try to raise hard limit without privilege.
        let raise = RLimit64 {
            rlim_cur: 100,
            rlim_max: 2000,
        };
        assert_eq!(
            do_sys_prlimit(&mut reg, 0, RLIMIT_NOFILE, Some(raise), &unpriv_cred()),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn nofile_clamped_without_cap() {
        let mut reg = ProcessLimitRegistry::new();
        let huge = RLimit64 {
            rlim_cur: u64::MAX,
            rlim_max: u64::MAX,
        };
        do_sys_prlimit(&mut reg, 0, RLIMIT_NOFILE, Some(huge), &unpriv_cred()).unwrap();
        let got = do_sys_prlimit(&mut reg, 0, RLIMIT_NOFILE, None, &unpriv_cred()).unwrap();
        assert_eq!(got.rlim_cur, RLIMIT_NOFILE_MAX);
        assert_eq!(got.rlim_max, RLIMIT_NOFILE_MAX);
    }

    #[test]
    fn nofile_not_clamped_with_cap() {
        let mut reg = ProcessLimitRegistry::new();
        let huge = RLimit64 {
            rlim_cur: 2_000_000,
            rlim_max: 2_000_000,
        };
        do_sys_prlimit(&mut reg, 0, RLIMIT_NOFILE, Some(huge), &priv_cred()).unwrap();
        let got = do_sys_prlimit(&mut reg, 0, RLIMIT_NOFILE, None, &priv_cred()).unwrap();
        assert_eq!(got.rlim_cur, 2_000_000);
    }

    #[test]
    fn bad_resource_rejected() {
        let mut reg = ProcessLimitRegistry::new();
        assert_eq!(
            do_sys_prlimit(&mut reg, 0, RLIM_NLIMITS, None, &priv_cred()),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn multiple_resources_independent() {
        let mut reg = ProcessLimitRegistry::new();
        let stack = RLimit64 {
            rlim_cur: 8 * 1024 * 1024,
            rlim_max: 64 * 1024 * 1024,
        };
        let data = RLimit64 {
            rlim_cur: 256 * 1024 * 1024,
            rlim_max: RLIM64_INFINITY,
        };
        do_sys_prlimit(&mut reg, 0, RLIMIT_STACK, Some(stack), &priv_cred()).unwrap();
        do_sys_prlimit(&mut reg, 0, RLIMIT_DATA, Some(data), &priv_cred()).unwrap();
        assert_eq!(
            do_sys_prlimit(&mut reg, 0, RLIMIT_STACK, None, &priv_cred()).unwrap(),
            stack
        );
        assert_eq!(
            do_sys_prlimit(&mut reg, 0, RLIMIT_DATA, None, &priv_cred()).unwrap(),
            data
        );
    }
}
