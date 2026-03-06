// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Resource limit checking and enforcement.
//!
//! Per-process soft/hard rlimit enforcement with Linux-compatible
//! defaults. Helpers for RLIMIT_NPROC, NOFILE, FSIZE, CORE, AS,
//! STACK, CPU, plus setrlimit with privilege checks.
//!
//! Reference: POSIX.1-2024 `<sys/resource.h>`, Linux `kernel/sys.c`.

use oncrix_lib::{Error, Result};

/// Resource limit type indices (Linux x86_64 ABI).
pub const RLIMIT_CPU: usize = 0;
pub const RLIMIT_FSIZE: usize = 1;
pub const RLIMIT_DATA: usize = 2;
pub const RLIMIT_STACK: usize = 3;
pub const RLIMIT_CORE: usize = 4;
pub const RLIMIT_RSS: usize = 5;
pub const RLIMIT_NPROC: usize = 6;
pub const RLIMIT_NOFILE: usize = 7;
pub const RLIMIT_MEMLOCK: usize = 8;
pub const RLIMIT_AS: usize = 9;
pub const RLIMIT_LOCKS: usize = 10;
pub const RLIMIT_SIGPENDING: usize = 11;
pub const RLIMIT_MSGQUEUE: usize = 12;
pub const RLIMIT_NICE: usize = 13;
pub const RLIMIT_RTPRIO: usize = 14;
pub const RLIMIT_RTTIME: usize = 15;
const RLIMIT_COUNT: usize = 16;

/// Unlimited sentinel value.
pub const RLIM_INFINITY: u64 = u64::MAX;

const MAX_PROCESSES: usize = 256;
const DEFAULT_NOFILE_SOFT: u64 = 1024;
const DEFAULT_NOFILE_HARD: u64 = 4096;
const DEFAULT_NPROC: u64 = 4096;
const DEFAULT_STACK_SOFT: u64 = 8 * 1024 * 1024;
const DEFAULT_CORE_SOFT: u64 = 0;
const DEFAULT_MEMLOCK_SOFT: u64 = 64 * 1024;
const DEFAULT_MSGQUEUE: u64 = 819200;
const DEFAULT_SIGPENDING: u64 = 4096;
const DEFAULT_RTPRIO: u64 = 0;
const DEFAULT_NICE: u64 = 0;

/// A single resource limit (soft + hard).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Rlimit {
    /// Current (soft) limit.
    pub rlim_cur: u64,
    /// Maximum (hard) limit.
    pub rlim_max: u64,
}

impl Rlimit {
    /// Unlimited resource limit.
    pub const fn unlimited() -> Self {
        Self {
            rlim_cur: RLIM_INFINITY,
            rlim_max: RLIM_INFINITY,
        }
    }

    /// Create a limit with specified soft and hard values.
    pub const fn new(soft: u64, hard: u64) -> Self {
        Self {
            rlim_cur: soft,
            rlim_max: hard,
        }
    }

    /// Check whether a value exceeds the soft limit.
    pub fn exceeds_soft(&self, value: u64) -> bool {
        self.rlim_cur != RLIM_INFINITY && value > self.rlim_cur
    }

    /// Check whether a value exceeds the hard limit.
    pub fn exceeds_hard(&self, value: u64) -> bool {
        self.rlim_max != RLIM_INFINITY && value > self.rlim_max
    }
}

/// Per-process resource limit set.
#[derive(Debug, Clone, Copy)]
struct ProcessRlimits {
    /// Array of rlimits indexed by resource constant.
    limits: [Rlimit; RLIMIT_COUNT],
    /// Process ID.
    pid: u64,
    /// Whether this slot is active.
    active: bool,
}

/// Enforcement result from a check operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckResult {
    /// Value is within limits.
    Allowed,
    /// Value exceeds the soft limit.
    SoftExceeded,
    /// Value exceeds the hard limit.
    HardExceeded,
}

/// Statistics for rlimit operations.
#[derive(Debug, Clone, Copy)]
pub struct RlimitStats {
    /// Total check operations performed.
    pub total_checks: u64,
    /// Total soft limit violations.
    pub soft_violations: u64,
    /// Total hard limit violations.
    pub hard_violations: u64,
    /// Total setrlimit calls.
    pub total_sets: u64,
}

/// Per-process resource limit checker.
pub struct RlimitChecker {
    /// Per-process rlimit sets.
    procs: [ProcessRlimits; MAX_PROCESSES],
    /// Statistics.
    stats: RlimitStats,
}

impl RlimitChecker {
    /// Create a new rlimit checker.
    pub const fn new() -> Self {
        let proc_rl = ProcessRlimits {
            limits: [Rlimit::unlimited(); RLIMIT_COUNT],
            pid: 0,
            active: false,
        };
        Self {
            procs: [proc_rl; MAX_PROCESSES],
            stats: RlimitStats {
                total_checks: 0,
                soft_violations: 0,
                hard_violations: 0,
                total_sets: 0,
            },
        }
    }

    /// Initialize default rlimits for a new process.
    pub fn init_rlimits(&mut self, pid: u64) -> Result<()> {
        let idx = self.alloc_slot(pid)?;
        let rl = &mut self.procs[idx];
        rl.limits = [Rlimit::unlimited(); RLIMIT_COUNT];
        // Apply Linux-compatible defaults.
        rl.limits[RLIMIT_NOFILE] = Rlimit::new(DEFAULT_NOFILE_SOFT, DEFAULT_NOFILE_HARD);
        rl.limits[RLIMIT_NPROC] = Rlimit::new(DEFAULT_NPROC, DEFAULT_NPROC);
        rl.limits[RLIMIT_STACK] = Rlimit::new(DEFAULT_STACK_SOFT, RLIM_INFINITY);
        rl.limits[RLIMIT_CORE] = Rlimit::new(DEFAULT_CORE_SOFT, RLIM_INFINITY);
        rl.limits[RLIMIT_MEMLOCK] = Rlimit::new(DEFAULT_MEMLOCK_SOFT, DEFAULT_MEMLOCK_SOFT);
        rl.limits[RLIMIT_MSGQUEUE] = Rlimit::new(DEFAULT_MSGQUEUE, DEFAULT_MSGQUEUE);
        rl.limits[RLIMIT_SIGPENDING] = Rlimit::new(DEFAULT_SIGPENDING, DEFAULT_SIGPENDING);
        rl.limits[RLIMIT_RTPRIO] = Rlimit::new(DEFAULT_RTPRIO, DEFAULT_RTPRIO);
        rl.limits[RLIMIT_NICE] = Rlimit::new(DEFAULT_NICE, DEFAULT_NICE);
        Ok(())
    }

    /// Check RLIMIT_NPROC (process count for this UID).
    pub fn check_nproc(&mut self, pid: u64, current_count: u64) -> Result<CheckResult> {
        self.check_resource(pid, RLIMIT_NPROC, current_count)
    }

    /// Check RLIMIT_NOFILE (open file descriptor count).
    pub fn check_nofile(&mut self, pid: u64, current_count: u64) -> Result<CheckResult> {
        self.check_resource(pid, RLIMIT_NOFILE, current_count)
    }

    /// Check RLIMIT_FSIZE (file size in bytes).
    pub fn check_fsize(&mut self, pid: u64, file_size: u64) -> Result<CheckResult> {
        self.check_resource(pid, RLIMIT_FSIZE, file_size)
    }

    /// Check RLIMIT_CORE (core dump size in bytes).
    pub fn check_core(&mut self, pid: u64, core_size: u64) -> Result<CheckResult> {
        self.check_resource(pid, RLIMIT_CORE, core_size)
    }

    /// Check RLIMIT_AS (address space size in bytes).
    pub fn check_as(&mut self, pid: u64, addr_space: u64) -> Result<CheckResult> {
        self.check_resource(pid, RLIMIT_AS, addr_space)
    }

    /// Check RLIMIT_STACK (stack size in bytes).
    pub fn check_stack(&mut self, pid: u64, stack_size: u64) -> Result<CheckResult> {
        self.check_resource(pid, RLIMIT_STACK, stack_size)
    }

    /// Check RLIMIT_CPU (CPU time in seconds).
    pub fn check_cpu(&mut self, pid: u64, cpu_seconds: u64) -> Result<CheckResult> {
        self.check_resource(pid, RLIMIT_CPU, cpu_seconds)
    }

    /// Get the current rlimit for a resource.
    pub fn getrlimit(&self, pid: u64, resource: usize) -> Result<Rlimit> {
        if resource >= RLIMIT_COUNT {
            return Err(Error::InvalidArgument);
        }
        let idx = self.find_proc(pid)?;
        Ok(self.procs[idx].limits[resource])
    }

    /// Set a resource limit (with privilege check).
    ///
    /// `privileged` should be true if the caller has
    /// CAP_SYS_RESOURCE or is root.
    pub fn setrlimit(
        &mut self,
        pid: u64,
        resource: usize,
        new: Rlimit,
        privileged: bool,
    ) -> Result<()> {
        if resource >= RLIMIT_COUNT {
            return Err(Error::InvalidArgument);
        }
        let idx = self.find_proc(pid)?;
        let current = &self.procs[idx].limits[resource];
        // Soft cannot exceed hard.
        if new.rlim_cur != RLIM_INFINITY
            && new.rlim_max != RLIM_INFINITY
            && new.rlim_cur > new.rlim_max
        {
            return Err(Error::InvalidArgument);
        }
        // Unprivileged cannot raise hard limit.
        if !privileged && new.rlim_max > current.rlim_max {
            return Err(Error::PermissionDenied);
        }
        self.procs[idx].limits[resource] = new;
        self.stats.total_sets += 1;
        Ok(())
    }

    /// Remove a process from the checker.
    pub fn remove_process(&mut self, pid: u64) -> Result<()> {
        let idx = self.find_proc(pid)?;
        self.procs[idx].active = false;
        self.procs[idx].pid = 0;
        Ok(())
    }

    /// Copy rlimits from parent to child (for fork).
    pub fn copy_rlimits(&mut self, parent_pid: u64, child_pid: u64) -> Result<()> {
        let parent_idx = self.find_proc(parent_pid)?;
        let limits = self.procs[parent_idx].limits;
        let child_idx = self.alloc_slot(child_pid)?;
        self.procs[child_idx].limits = limits;
        Ok(())
    }

    /// Return statistics.
    pub fn stats(&self) -> &RlimitStats {
        &self.stats
    }

    // ── Internal helpers ────────────────────────────────────────

    /// Generic resource check.
    fn check_resource(&mut self, pid: u64, resource: usize, value: u64) -> Result<CheckResult> {
        if resource >= RLIMIT_COUNT {
            return Err(Error::InvalidArgument);
        }
        let idx = self.find_proc(pid)?;
        let lim = &self.procs[idx].limits[resource];
        self.stats.total_checks += 1;
        if lim.exceeds_hard(value) {
            self.stats.hard_violations += 1;
            return Ok(CheckResult::HardExceeded);
        }
        if lim.exceeds_soft(value) {
            self.stats.soft_violations += 1;
            return Ok(CheckResult::SoftExceeded);
        }
        Ok(CheckResult::Allowed)
    }

    /// Find the slot index for a given pid.
    fn find_proc(&self, pid: u64) -> Result<usize> {
        self.procs
            .iter()
            .position(|p| p.active && p.pid == pid)
            .ok_or(Error::NotFound)
    }

    /// Allocate a new slot for a process.
    fn alloc_slot(&mut self, pid: u64) -> Result<usize> {
        // Check for duplicate.
        if self.procs.iter().any(|p| p.active && p.pid == pid) {
            return Err(Error::AlreadyExists);
        }
        let pos = self
            .procs
            .iter()
            .position(|p| !p.active)
            .ok_or(Error::OutOfMemory)?;
        self.procs[pos].pid = pid;
        self.procs[pos].active = true;
        Ok(pos)
    }
}
