// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getcpu` syscall handler.
//!
//! Returns the CPU and NUMA node the calling thread is currently running on.
//! This is a performance-sensitive syscall often implemented as a vDSO entry.
//!
//! The third `tcache` argument is unused since Linux 2.6.24 and must be NULL.
//!
//! # POSIX Conformance
//! `getcpu` is a Linux-specific extension not in POSIX.1-2024.

use oncrix_lib::{Error, Result};

/// Result of a `getcpu` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GetCpuResult {
    /// CPU index on which the calling thread is currently executing.
    pub cpu: u32,
    /// NUMA node to which the CPU belongs.
    pub node: u32,
}

impl GetCpuResult {
    /// Construct a new result.
    pub const fn new(cpu: u32, node: u32) -> Self {
        Self { cpu, node }
    }
}

/// Arguments for the `getcpu` syscall.
#[derive(Debug, Clone, Copy)]
pub struct GetCpuArgs {
    /// User-space pointer to write the CPU number (NULL = discard).
    pub cpu_ptr: u64,
    /// User-space pointer to write the NUMA node number (NULL = discard).
    pub node_ptr: u64,
    /// Must be NULL (legacy `tcache` argument, unused since 2.6.24).
    pub tcache_ptr: u64,
}

impl GetCpuArgs {
    /// Construct from raw syscall register values.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] — `tcache_ptr` is non-null.
    pub fn from_raw(cpu_ptr: u64, node_ptr: u64, tcache_ptr: u64) -> Result<Self> {
        if tcache_ptr != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            cpu_ptr,
            node_ptr,
            tcache_ptr,
        })
    }

    /// Returns `true` if the CPU output is requested.
    pub fn wants_cpu(self) -> bool {
        self.cpu_ptr != 0
    }

    /// Returns `true` if the NUMA node output is requested.
    pub fn wants_node(self) -> bool {
        self.node_ptr != 0
    }
}

/// Handle the `getcpu` syscall.
///
/// Returns the current CPU and NUMA node for the calling thread.
///
/// # Errors
/// - [`Error::InvalidArgument`] — tcache_ptr is non-null.
pub fn sys_getcpu(args: GetCpuArgs) -> Result<GetCpuResult> {
    // A full implementation would read the per-CPU variables (current cpu/node)
    // from the kernel's per-CPU data or the vDSO mapping.
    let _ = args;
    Ok(GetCpuResult::new(0, 0))
}

/// Raw syscall entry point for `getcpu`.
///
/// # Arguments
/// * `cpu_ptr` — pointer to write CPU number (register a0), or 0 to discard.
/// * `node_ptr` — pointer to write NUMA node (register a1), or 0 to discard.
/// * `tcache_ptr` — must be 0 (register a2).
///
/// # Returns
/// `0` on success, negative errno on failure.
pub fn syscall_getcpu(cpu_ptr: u64, node_ptr: u64, tcache_ptr: u64) -> i64 {
    let args = match GetCpuArgs::from_raw(cpu_ptr, node_ptr, tcache_ptr) {
        Ok(a) => a,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_getcpu(args) {
        Ok(_result) => {
            // Real implementation: write cpu and node to user pointers.
            0
        }
        Err(Error::InvalidArgument) => -(oncrix_lib::errno::EINVAL as i64),
        Err(_) => -(oncrix_lib::errno::EINVAL as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonzero_tcache_rejected() {
        assert!(GetCpuArgs::from_raw(0x1000, 0x2000, 0x3000).is_err());
    }

    #[test]
    fn test_both_ptrs_null_ok() {
        let args = GetCpuArgs::from_raw(0, 0, 0).unwrap();
        assert!(!args.wants_cpu());
        assert!(!args.wants_node());
    }

    #[test]
    fn test_cpu_ptr_only() {
        let args = GetCpuArgs::from_raw(0x1000, 0, 0).unwrap();
        assert!(args.wants_cpu());
        assert!(!args.wants_node());
    }

    #[test]
    fn test_both_ptrs() {
        let args = GetCpuArgs::from_raw(0x1000, 0x2000, 0).unwrap();
        assert!(args.wants_cpu());
        assert!(args.wants_node());
    }

    #[test]
    fn test_result_construction() {
        let r = GetCpuResult::new(3, 1);
        assert_eq!(r.cpu, 3);
        assert_eq!(r.node, 1);
    }

    #[test]
    fn test_syscall_success() {
        let ret = syscall_getcpu(0x1000, 0x2000, 0);
        assert_eq!(ret, 0);
    }
}
