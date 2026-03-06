// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `setrlimit(2)` syscall handler.
//!
//! Sets the soft and/or hard resource limit for a resource.  The soft limit
//! is the enforced upper bound; the hard limit is the ceiling to which
//! unprivileged processes may raise the soft limit.  Only a privileged process
//! (`CAP_SYS_RESOURCE`) may raise the hard limit.
//!
//! # Syscall signature
//!
//! ```text
//! int setrlimit(int resource, const struct rlimit *rlim);
//! ```
//!
//! # POSIX reference
//!
//! POSIX.1-2024 §setrlimit — `<sys/resource.h>`.
//!
//! # References
//!
//! - Linux: `kernel/sys.c` `do_prlimit()`
//! - `setrlimit(2)` man page
//! - `include/uapi/linux/resource.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Resource constants
// ---------------------------------------------------------------------------

/// CPU time limit (seconds).
pub const RLIMIT_CPU: u32 = 0;
/// Maximum file size (bytes).
pub const RLIMIT_FSIZE: u32 = 1;
/// Maximum data segment size (bytes).
pub const RLIMIT_DATA: u32 = 2;
/// Maximum stack size (bytes).
pub const RLIMIT_STACK: u32 = 3;
/// Maximum core file size (bytes).
pub const RLIMIT_CORE: u32 = 4;
/// Maximum RSS (bytes, advisory).
pub const RLIMIT_RSS: u32 = 5;
/// Maximum number of processes.
pub const RLIMIT_NPROC: u32 = 6;
/// Maximum number of open files.
pub const RLIMIT_NOFILE: u32 = 7;
/// Maximum locked memory (bytes).
pub const RLIMIT_MEMLOCK: u32 = 8;
/// Maximum virtual address space (bytes).
pub const RLIMIT_AS: u32 = 9;
/// Maximum file locks held.
pub const RLIMIT_LOCKS: u32 = 10;
/// Maximum pending signals.
pub const RLIMIT_SIGPENDING: u32 = 11;
/// Maximum POSIX message queue bytes.
pub const RLIMIT_MSGQUEUE: u32 = 12;
/// Maximum realtime scheduling priority.
pub const RLIMIT_RTPRIO: u32 = 13;
/// Maximum realtime scheduling time (μs, 0 = unlimited).
pub const RLIMIT_RTTIME: u32 = 14;

/// Number of recognised resource types.
pub const RLIM_NLIMITS: u32 = 15;

/// Sentinel meaning "no limit".
pub const RLIM_INFINITY: u64 = u64::MAX;

// ---------------------------------------------------------------------------
// RLimit — resource limit pair
// ---------------------------------------------------------------------------

/// Resource limit pair (soft + hard).
///
/// Mirrors `struct rlimit` from `<sys/resource.h>`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RLimit {
    /// Soft limit (currently enforced).
    pub rlim_cur: u64,
    /// Hard limit (ceiling for the soft limit).
    pub rlim_max: u64,
}

impl RLimit {
    /// Unlimited limit pair.
    pub const UNLIMITED: Self = Self {
        rlim_cur: RLIM_INFINITY,
        rlim_max: RLIM_INFINITY,
    };

    /// Return `true` if the soft limit exceeds the hard limit.
    pub const fn is_soft_exceeding_hard(&self) -> bool {
        self.rlim_cur != RLIM_INFINITY
            && self.rlim_max != RLIM_INFINITY
            && self.rlim_cur > self.rlim_max
    }
}

impl Default for RLimit {
    fn default() -> Self {
        Self::UNLIMITED
    }
}

// ---------------------------------------------------------------------------
// Caller credentials
// ---------------------------------------------------------------------------

/// Credentials needed for `setrlimit` permission checks.
#[derive(Debug, Clone, Copy)]
pub struct SetrlimitCred {
    /// True if the caller has `CAP_SYS_RESOURCE`.
    pub has_sys_resource: bool,
}

// ---------------------------------------------------------------------------
// RlimitTable — per-process limit storage
// ---------------------------------------------------------------------------

/// Per-process resource limit table.
pub struct RlimitTable {
    limits: [RLimit; RLIM_NLIMITS as usize],
}

impl RlimitTable {
    /// Create a table with all limits set to `RLIM_INFINITY`.
    pub const fn new() -> Self {
        Self {
            limits: [const { RLimit::UNLIMITED }; RLIM_NLIMITS as usize],
        }
    }

    /// Return the current limit for `resource`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] for an out-of-range resource ID.
    pub fn get(&self, resource: u32) -> Result<RLimit> {
        if resource >= RLIM_NLIMITS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.limits[resource as usize])
    }

    /// Set the limit for `resource`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] for an out-of-range resource ID.
    pub fn set(&mut self, resource: u32, limit: RLimit) -> Result<()> {
        if resource >= RLIM_NLIMITS {
            return Err(Error::InvalidArgument);
        }
        self.limits[resource as usize] = limit;
        Ok(())
    }
}

impl Default for RlimitTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate a `setrlimit` call.
///
/// Checks:
/// 1. `resource` is in range.
/// 2. `rlim.rlim_cur` does not exceed `rlim.rlim_max`.
/// 3. Unprivileged callers cannot raise the hard limit above the current one.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — bad resource or soft > hard.
/// * [`Error::PermissionDenied`] — unprivileged raise of hard limit.
pub fn validate_setrlimit(
    resource: u32,
    new_limit: &RLimit,
    current: &RLimit,
    cred: &SetrlimitCred,
) -> Result<()> {
    if resource >= RLIM_NLIMITS {
        return Err(Error::InvalidArgument);
    }

    // Soft must not exceed hard.
    if new_limit.is_soft_exceeding_hard() {
        return Err(Error::InvalidArgument);
    }

    // Unprivileged: may not raise the hard limit.
    if !cred.has_sys_resource {
        let cur_hard = current.rlim_max;
        let new_hard = new_limit.rlim_max;

        // Raising = new > current (and current is not infinity).
        let raises_hard = if cur_hard == RLIM_INFINITY {
            new_hard != RLIM_INFINITY
        } else {
            new_hard != RLIM_INFINITY && new_hard > cur_hard
        };

        if raises_hard {
            return Err(Error::PermissionDenied);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// sys_setrlimit — entry point
// ---------------------------------------------------------------------------

/// Handler for `setrlimit(2)`.
///
/// Applies `new_limit` for `resource` after permission and consistency checks.
///
/// # Arguments
///
/// * `table`     — Per-process resource limit table.
/// * `resource`  — Resource ID (`RLIMIT_*`).
/// * `new_limit` — New soft/hard limit pair.
/// * `cred`      — Caller credentials.
///
/// # Errors
///
/// See [`validate_setrlimit`].
pub fn sys_setrlimit(
    table: &mut RlimitTable,
    resource: u32,
    new_limit: &RLimit,
    cred: &SetrlimitCred,
) -> Result<()> {
    let current = table.get(resource)?;
    validate_setrlimit(resource, new_limit, &current, cred)?;
    table.set(resource, *new_limit)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn priv_cred() -> SetrlimitCred {
        SetrlimitCred {
            has_sys_resource: true,
        }
    }
    fn unpriv_cred() -> SetrlimitCred {
        SetrlimitCred {
            has_sys_resource: false,
        }
    }

    #[test]
    fn set_and_get() {
        let mut t = RlimitTable::new();
        let lim = RLimit {
            rlim_cur: 1024,
            rlim_max: 4096,
        };
        sys_setrlimit(&mut t, RLIMIT_NOFILE, &lim, &priv_cred()).unwrap();
        assert_eq!(t.get(RLIMIT_NOFILE).unwrap(), lim);
    }

    #[test]
    fn soft_exceeds_hard_rejected() {
        let mut t = RlimitTable::new();
        let bad = RLimit {
            rlim_cur: 8192,
            rlim_max: 4096,
        };
        assert_eq!(
            sys_setrlimit(&mut t, RLIMIT_NOFILE, &bad, &priv_cred()),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unpriv_lower_hard() {
        let mut t = RlimitTable::new();
        // Lower hard: allowed even without privilege.
        let lim = RLimit {
            rlim_cur: 512,
            rlim_max: 1024,
        };
        sys_setrlimit(&mut t, RLIMIT_NOFILE, &lim, &unpriv_cred()).unwrap();
        assert_eq!(t.get(RLIMIT_NOFILE).unwrap().rlim_max, 1024);
    }

    #[test]
    fn unpriv_raise_hard_denied() {
        let mut t = RlimitTable::new();
        // First set current hard to 1024.
        sys_setrlimit(
            &mut t,
            RLIMIT_NOFILE,
            &RLimit {
                rlim_cur: 512,
                rlim_max: 1024,
            },
            &priv_cred(),
        )
        .unwrap();
        // Try to raise hard to 2048 without privilege.
        assert_eq!(
            sys_setrlimit(
                &mut t,
                RLIMIT_NOFILE,
                &RLimit {
                    rlim_cur: 512,
                    rlim_max: 2048
                },
                &unpriv_cred()
            ),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn invalid_resource_rejected() {
        let mut t = RlimitTable::new();
        assert_eq!(
            sys_setrlimit(&mut t, RLIM_NLIMITS, &RLimit::UNLIMITED, &priv_cred()),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn priv_raise_hard_allowed() {
        let mut t = RlimitTable::new();
        sys_setrlimit(
            &mut t,
            RLIMIT_NOFILE,
            &RLimit {
                rlim_cur: 512,
                rlim_max: 1024,
            },
            &priv_cred(),
        )
        .unwrap();
        sys_setrlimit(
            &mut t,
            RLIMIT_NOFILE,
            &RLimit {
                rlim_cur: 1024,
                rlim_max: 65536,
            },
            &priv_cred(),
        )
        .unwrap();
        assert_eq!(t.get(RLIMIT_NOFILE).unwrap().rlim_max, 65536);
    }
}
