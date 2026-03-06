// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Resource limit query helpers shared by `getrlimit`, `setrlimit`, and
//! `prlimit64`.
//!
//! Provides resource-ID classification, default limit tables, and
//! cross-version conversion utilities (`rlimit` ↔ `rlimit64`).
//!
//! # POSIX reference
//!
//! POSIX.1-2024 §getrlimit — `<sys/resource.h>`.
//!
//! # References
//!
//! - Linux: `include/uapi/linux/resource.h`
//! - `getrlimit(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Resource ID constants
// ---------------------------------------------------------------------------

/// CPU time (seconds).
pub const RLIMIT_CPU: u32 = 0;
/// File size (bytes).
pub const RLIMIT_FSIZE: u32 = 1;
/// Data segment (bytes).
pub const RLIMIT_DATA: u32 = 2;
/// Stack size (bytes).
pub const RLIMIT_STACK: u32 = 3;
/// Core dump size (bytes).
pub const RLIMIT_CORE: u32 = 4;
/// Maximum RSS (bytes).
pub const RLIMIT_RSS: u32 = 5;
/// Maximum processes.
pub const RLIMIT_NPROC: u32 = 6;
/// Open files.
pub const RLIMIT_NOFILE: u32 = 7;
/// Locked memory (bytes).
pub const RLIMIT_MEMLOCK: u32 = 8;
/// Virtual address space (bytes).
pub const RLIMIT_AS: u32 = 9;
/// File locks.
pub const RLIMIT_LOCKS: u32 = 10;
/// Pending signals.
pub const RLIMIT_SIGPENDING: u32 = 11;
/// POSIX MQ bytes.
pub const RLIMIT_MSGQUEUE: u32 = 12;
/// RT priority.
pub const RLIMIT_RTPRIO: u32 = 13;
/// RT scheduling time (μs).
pub const RLIMIT_RTTIME: u32 = 14;

/// Number of resource IDs.
pub const RLIM_NLIMITS: u32 = 15;

/// 64-bit infinity sentinel.
pub const RLIM64_INFINITY: u64 = u64::MAX;
/// 32-bit infinity sentinel.
pub const RLIM32_INFINITY: u32 = u32::MAX;

// ---------------------------------------------------------------------------
// ResourceClass — classification helper
// ---------------------------------------------------------------------------

/// Classification of a resource limit type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceClass {
    /// Memory-related (bytes).
    Memory,
    /// Count-related (files, processes, signals).
    Count,
    /// Time-related (seconds or microseconds).
    Time,
    /// Priority-related.
    Priority,
}

/// Classify a resource ID.
///
/// # Errors
///
/// [`Error::InvalidArgument`] for unknown resource IDs.
pub fn classify_resource(resource: u32) -> Result<ResourceClass> {
    match resource {
        RLIMIT_FSIZE | RLIMIT_DATA | RLIMIT_STACK | RLIMIT_CORE | RLIMIT_RSS | RLIMIT_MEMLOCK
        | RLIMIT_AS => Ok(ResourceClass::Memory),
        RLIMIT_NPROC | RLIMIT_NOFILE | RLIMIT_LOCKS | RLIMIT_SIGPENDING | RLIMIT_MSGQUEUE => {
            Ok(ResourceClass::Count)
        }
        RLIMIT_CPU | RLIMIT_RTTIME => Ok(ResourceClass::Time),
        RLIMIT_RTPRIO => Ok(ResourceClass::Priority),
        r if r >= RLIM_NLIMITS => Err(Error::InvalidArgument),
        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// DefaultLimits — kernel default resource limits
// ---------------------------------------------------------------------------

/// 64-bit resource limit pair.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rlimit64 {
    /// Soft limit.
    pub rlim_cur: u64,
    /// Hard limit.
    pub rlim_max: u64,
}

impl Rlimit64 {
    /// Unlimited limit pair.
    pub const UNLIMITED: Self = Self {
        rlim_cur: RLIM64_INFINITY,
        rlim_max: RLIM64_INFINITY,
    };

    /// Bounded limit pair.
    pub const fn bounded(cur: u64, max: u64) -> Self {
        Self {
            rlim_cur: cur,
            rlim_max: max,
        }
    }
}

impl Default for Rlimit64 {
    fn default() -> Self {
        Self::UNLIMITED
    }
}

/// 32-bit resource limit pair.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rlimit32 {
    /// Soft limit.
    pub rlim_cur: u32,
    /// Hard limit.
    pub rlim_max: u32,
}

impl Default for Rlimit32 {
    fn default() -> Self {
        Self {
            rlim_cur: RLIM32_INFINITY,
            rlim_max: RLIM32_INFINITY,
        }
    }
}

/// Default resource limits table indexed by resource ID.
const DEFAULT_LIMITS: [Rlimit64; RLIM_NLIMITS as usize] = [
    Rlimit64::UNLIMITED,                                 // RLIMIT_CPU
    Rlimit64::UNLIMITED,                                 // RLIMIT_FSIZE
    Rlimit64::UNLIMITED,                                 // RLIMIT_DATA
    Rlimit64::bounded(8 * 1024 * 1024, RLIM64_INFINITY), // RLIMIT_STACK 8 MiB soft
    Rlimit64::bounded(0, RLIM64_INFINITY),               // RLIMIT_CORE (disabled by default)
    Rlimit64::UNLIMITED,                                 // RLIMIT_RSS
    Rlimit64::UNLIMITED,                                 // RLIMIT_NPROC
    Rlimit64::bounded(1024, 4096),                       // RLIMIT_NOFILE
    Rlimit64::bounded(64 * 1024, RLIM64_INFINITY),       // RLIMIT_MEMLOCK
    Rlimit64::UNLIMITED,                                 // RLIMIT_AS
    Rlimit64::UNLIMITED,                                 // RLIMIT_LOCKS
    Rlimit64::UNLIMITED,                                 // RLIMIT_SIGPENDING
    Rlimit64::bounded(819200, RLIM64_INFINITY),          // RLIMIT_MSGQUEUE
    Rlimit64::bounded(0, 0),                             // RLIMIT_RTPRIO (disabled by default)
    Rlimit64::UNLIMITED,                                 // RLIMIT_RTTIME
];

/// Return the kernel default limit for `resource`.
///
/// # Errors
///
/// [`Error::InvalidArgument`] for out-of-range `resource`.
pub fn default_limit(resource: u32) -> Result<Rlimit64> {
    if resource >= RLIM_NLIMITS {
        return Err(Error::InvalidArgument);
    }
    Ok(DEFAULT_LIMITS[resource as usize])
}

// ---------------------------------------------------------------------------
// Conversion helpers — rlimit64 ↔ rlimit32
// ---------------------------------------------------------------------------

/// Convert a 64-bit limit to 32-bit.
///
/// Values that exceed `RLIM32_INFINITY - 1` are capped at `RLIM32_INFINITY`.
pub fn rlimit64_to_32(l: &Rlimit64) -> Rlimit32 {
    let cap = |v: u64| {
        if v == RLIM64_INFINITY || v > RLIM32_INFINITY as u64 {
            RLIM32_INFINITY
        } else {
            v as u32
        }
    };
    Rlimit32 {
        rlim_cur: cap(l.rlim_cur),
        rlim_max: cap(l.rlim_max),
    }
}

/// Convert a 32-bit limit to 64-bit.
pub const fn rlimit32_to_64(l: &Rlimit32) -> Rlimit64 {
    const fn expand(v: u32) -> u64 {
        if v == RLIM32_INFINITY {
            RLIM64_INFINITY
        } else {
            v as u64
        }
    }
    Rlimit64 {
        rlim_cur: expand(l.rlim_cur),
        rlim_max: expand(l.rlim_max),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_memory() {
        assert_eq!(classify_resource(RLIMIT_DATA), Ok(ResourceClass::Memory));
        assert_eq!(classify_resource(RLIMIT_AS), Ok(ResourceClass::Memory));
    }

    #[test]
    fn classify_count() {
        assert_eq!(classify_resource(RLIMIT_NOFILE), Ok(ResourceClass::Count));
    }

    #[test]
    fn classify_time() {
        assert_eq!(classify_resource(RLIMIT_CPU), Ok(ResourceClass::Time));
    }

    #[test]
    fn classify_unknown() {
        assert_eq!(classify_resource(RLIM_NLIMITS), Err(Error::InvalidArgument));
    }

    #[test]
    fn default_nofile() {
        let lim = default_limit(RLIMIT_NOFILE).unwrap();
        assert_eq!(lim.rlim_cur, 1024);
        assert_eq!(lim.rlim_max, 4096);
    }

    #[test]
    fn default_stack_soft() {
        let lim = default_limit(RLIMIT_STACK).unwrap();
        assert_eq!(lim.rlim_cur, 8 * 1024 * 1024);
    }

    #[test]
    fn rlimit_conversion_roundtrip() {
        let l64 = Rlimit64::bounded(1024, 4096);
        let l32 = rlimit64_to_32(&l64);
        let back = rlimit32_to_64(&l32);
        assert_eq!(back, l64);
    }

    #[test]
    fn rlimit_infinity_conversion() {
        let l64 = Rlimit64::UNLIMITED;
        let l32 = rlimit64_to_32(&l64);
        assert_eq!(l32.rlim_cur, RLIM32_INFINITY);
        let back = rlimit32_to_64(&l32);
        assert_eq!(back, l64);
    }

    #[test]
    fn out_of_range_resource() {
        assert_eq!(default_limit(999), Err(Error::InvalidArgument));
    }
}
