// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX resource limits (`rlimit`).
//!
//! Provides per-process resource limits compatible with the POSIX
//! `getrlimit` / `setrlimit` / `prlimit` interfaces. Resource
//! constants and semantics follow the Linux x86_64 ABI for
//! interoperability.
//!
//! Each process holds an [`RlimitSet`] that tracks both the soft
//! (current) and hard (maximum) limits for each resource type.
//! Unprivileged processes may raise soft limits up to the hard
//! limit but may never exceed the hard limit.
//!
//! Reference: POSIX.1-2024 `<sys/resource.h>`, `getrlimit()`.

use oncrix_lib::{Error, Result};

// ── Resource type constants (Linux x86_64 ABI) ─────────────────

/// Maximum CPU time in seconds.
pub const RLIMIT_CPU: u32 = 0;
/// Maximum file size in bytes.
pub const RLIMIT_FSIZE: u32 = 1;
/// Maximum data segment size in bytes.
pub const RLIMIT_DATA: u32 = 2;
/// Maximum stack size in bytes.
pub const RLIMIT_STACK: u32 = 3;
/// Maximum core file size in bytes.
pub const RLIMIT_CORE: u32 = 4;
/// Maximum resident set size in bytes.
pub const RLIMIT_RSS: u32 = 5;
/// Maximum number of processes per real UID.
pub const RLIMIT_NPROC: u32 = 6;
/// Maximum number of open file descriptors.
pub const RLIMIT_NOFILE: u32 = 7;
/// Maximum bytes lockable in memory.
pub const RLIMIT_MEMLOCK: u32 = 8;
/// Maximum virtual memory (address space) size in bytes.
pub const RLIMIT_AS: u32 = 9;
/// Maximum number of file locks.
pub const RLIMIT_LOCKS: u32 = 10;
/// Maximum number of pending signals.
pub const RLIMIT_SIGPENDING: u32 = 11;
/// Maximum bytes in POSIX message queues.
pub const RLIMIT_MSGQUEUE: u32 = 12;
/// Maximum nice priority (ceiling).
pub const RLIMIT_NICE: u32 = 13;
/// Maximum real-time scheduling priority.
pub const RLIMIT_RTPRIO: u32 = 14;
/// Maximum real-time CPU time (microseconds) without blocking.
pub const RLIMIT_RTTIME: u32 = 15;

/// Total number of resource limit types.
pub const RLIM_NLIMITS: usize = 16;

/// Value indicating no limit (infinity).
pub const RLIM_INFINITY: u64 = u64::MAX;

// ── Default values ──────────────────────────────────────────────

/// Default soft limit for `RLIMIT_NOFILE`.
const DEFAULT_NOFILE_CUR: u64 = 256;
/// Default hard limit for `RLIMIT_NOFILE`.
const DEFAULT_NOFILE_MAX: u64 = 1024;

/// Default soft limit for `RLIMIT_STACK` (8 MiB).
const DEFAULT_STACK_CUR: u64 = 8 * 1024 * 1024;
/// Default hard limit for `RLIMIT_STACK` (64 MiB).
const DEFAULT_STACK_MAX: u64 = 64 * 1024 * 1024;

/// Default soft limit for `RLIMIT_NPROC`.
const DEFAULT_NPROC_CUR: u64 = 256;
/// Default hard limit for `RLIMIT_NPROC`.
const DEFAULT_NPROC_MAX: u64 = 256;

// ── Rlimit struct ───────────────────────────────────────────────

/// A single resource limit with soft (current) and hard (maximum)
/// values.
///
/// Matches the POSIX `struct rlimit` layout for direct
/// `copy_to_user` / `copy_from_user` compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Rlimit {
    /// Soft (current, enforced) limit.
    pub rlim_cur: u64,
    /// Hard (ceiling) limit — only a privileged process may raise
    /// this.
    pub rlim_max: u64,
}

impl Rlimit {
    /// Create a new limit pair.
    pub const fn new(cur: u64, max: u64) -> Self {
        Self {
            rlim_cur: cur,
            rlim_max: max,
        }
    }

    /// Create a limit where both soft and hard are `RLIM_INFINITY`.
    pub const fn infinity() -> Self {
        Self {
            rlim_cur: RLIM_INFINITY,
            rlim_max: RLIM_INFINITY,
        }
    }
}

impl core::fmt::Display for Rlimit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let fmt_val = |v: u64| -> &str {
            if v == RLIM_INFINITY {
                "unlimited"
            } else {
                // Cannot format dynamic u64 in no_std Display
                // without allocation; use a sentinel label.
                "bounded"
            }
        };
        write!(
            f,
            "Rlimit {{ cur: {}, max: {} }}",
            fmt_val(self.rlim_cur),
            fmt_val(self.rlim_max),
        )
    }
}

// ── RlimitSet ───────────────────────────────────────────────────

/// Per-process set of resource limits.
///
/// Contains one [`Rlimit`] entry for each of the
/// [`RLIM_NLIMITS`] resource types. Cloned on `fork()` so
/// children inherit the parent's limits.
#[derive(Debug, Clone)]
pub struct RlimitSet {
    /// Array of limits indexed by resource constant.
    limits: [Rlimit; RLIM_NLIMITS],
}

impl Default for RlimitSet {
    fn default() -> Self {
        Self::new()
    }
}

impl RlimitSet {
    /// Create a new limit set with sensible defaults.
    ///
    /// - `RLIMIT_NOFILE`: cur=256, max=1024
    /// - `RLIMIT_STACK`:  cur=8 MiB, max=64 MiB
    /// - `RLIMIT_NPROC`:  cur=256, max=256
    /// - All others:      `RLIM_INFINITY` (no limit)
    pub const fn new() -> Self {
        let mut limits = [Rlimit::infinity(); RLIM_NLIMITS];

        limits[RLIMIT_NOFILE as usize] = Rlimit::new(DEFAULT_NOFILE_CUR, DEFAULT_NOFILE_MAX);
        limits[RLIMIT_STACK as usize] = Rlimit::new(DEFAULT_STACK_CUR, DEFAULT_STACK_MAX);
        limits[RLIMIT_NPROC as usize] = Rlimit::new(DEFAULT_NPROC_CUR, DEFAULT_NPROC_MAX);

        Self { limits }
    }

    /// Get the current limit for `resource`.
    ///
    /// Returns `Error::InvalidArgument` if `resource` is out of
    /// range.
    pub fn get(&self, resource: u32) -> Result<Rlimit> {
        let idx = resource as usize;
        if idx >= RLIM_NLIMITS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.limits[idx])
    }

    /// Set a new limit for `resource`, returning the previous value.
    ///
    /// Validates that `new.rlim_cur <= new.rlim_max`. An
    /// unprivileged caller should additionally verify that the new
    /// hard limit does not exceed the old hard limit (enforced at
    /// the syscall layer).
    ///
    /// Returns `Error::InvalidArgument` if `resource` is out of
    /// range or `new.rlim_cur > new.rlim_max`.
    pub fn set(&mut self, resource: u32, new: &Rlimit) -> Result<Rlimit> {
        let idx = resource as usize;
        if idx >= RLIM_NLIMITS {
            return Err(Error::InvalidArgument);
        }
        // Soft limit must not exceed hard limit.
        if new.rlim_cur > new.rlim_max {
            return Err(Error::InvalidArgument);
        }
        let old = self.limits[idx];
        self.limits[idx] = *new;
        Ok(old)
    }

    /// Check whether `value` is within the soft limit for
    /// `resource`.
    ///
    /// Returns `true` if `value <= rlim_cur` (i.e. the usage is
    /// permitted), or `false` if it would exceed the limit.
    /// Out-of-range resources always return `false`.
    pub fn check(&self, resource: u32, value: u64) -> bool {
        let idx = resource as usize;
        if idx >= RLIM_NLIMITS {
            return false;
        }
        value <= self.limits[idx].rlim_cur
    }
}

impl core::fmt::Display for RlimitSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "RlimitSet({} resources)", RLIM_NLIMITS)
    }
}
