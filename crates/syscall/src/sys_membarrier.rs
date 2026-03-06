// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `membarrier(2)` syscall handler — process-wide and system-wide memory barriers.
//!
//! `membarrier` allows a process to issue memory barrier instructions on a set
//! of threads without requiring those threads to execute barrier instructions
//! themselves.  The primary use case is efficient user-space RCU
//! implementations where the writer issues `membarrier` instead of broadcasting
//! memory barriers to all readers.
//!
//! # Syscall signature
//!
//! ```text
//! int membarrier(int cmd, unsigned int flags, int cpu_id);
//! ```
//!
//! # Commands
//!
//! | Command | Description |
//! |---------|-------------|
//! | `MEMBARRIER_CMD_QUERY` | Return supported command bitmask |
//! | `MEMBARRIER_CMD_GLOBAL` | Issue barrier on all threads system-wide |
//! | `MEMBARRIER_CMD_PRIVATE_EXPEDITED` | IPI-based barrier within the process |
//! | `MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED` | Register for private expedited |
//! | `MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE` | Barrier + icache sync |
//! | `MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE` | Register sync-core |
//!
//! # Registration model
//!
//! Expedited commands require prior registration.  Registration enables the
//! kernel to track which processes participate, allowing it to skip non-
//! participating CPUs when issuing IPIs.
//!
//! # POSIX conformance
//!
//! `membarrier` is a Linux extension (since Linux 4.3).  Not part of
//! POSIX.1-2024.  The memory-ordering semantics are specified in the Linux
//! `membarrier(2)` man page.
//!
//! # References
//!
//! - Linux: `kernel/sched/membarrier.c`
//! - `membarrier(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Command constants
// ---------------------------------------------------------------------------

/// Query which commands are supported; returns a bitmask.
pub const MEMBARRIER_CMD_QUERY: i32 = 0;

/// Issue a full memory barrier on all threads system-wide.
///
/// Slower than expedited variants; does not require registration.
pub const MEMBARRIER_CMD_GLOBAL: i32 = 1;

/// Issue a memory barrier on all threads registered for global expedited.
pub const MEMBARRIER_CMD_GLOBAL_EXPEDITED: i32 = 2;

/// Register the calling process for `MEMBARRIER_CMD_GLOBAL_EXPEDITED`.
pub const MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED: i32 = 4;

/// Issue an IPI-based memory barrier within the calling process only.
///
/// Must be preceded by `MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED`.
pub const MEMBARRIER_CMD_PRIVATE_EXPEDITED: i32 = 8;

/// Register the calling process for `MEMBARRIER_CMD_PRIVATE_EXPEDITED`.
pub const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED: i32 = 16;

/// Issue a private expedited barrier that also synchronises the icache.
pub const MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE: i32 = 32;

/// Register for `MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE`.
pub const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE: i32 = 64;

/// Issue a private expedited barrier for restartable sequences (rseq).
pub const MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ: i32 = 128;

/// Register for `MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ`.
pub const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ: i32 = 256;

/// Bitmask of all supported commands returned by `MEMBARRIER_CMD_QUERY`.
const SUPPORTED_CMDS: i32 = MEMBARRIER_CMD_GLOBAL
    | MEMBARRIER_CMD_GLOBAL_EXPEDITED
    | MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED
    | MEMBARRIER_CMD_PRIVATE_EXPEDITED
    | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED
    | MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE
    | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE
    | MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ
    | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ;

// ---------------------------------------------------------------------------
// Flag constants
// ---------------------------------------------------------------------------

/// No flags; the default for most commands.
pub const MEMBARRIER_CMD_FLAG_NONE: u32 = 0;

/// Target a specific CPU by index (valid only for rseq commands).
pub const MEMBARRIER_CMD_FLAG_CPU: u32 = 1 << 0;

/// All valid flag bits.
const FLAGS_MASK: u32 = MEMBARRIER_CMD_FLAG_CPU;

// ---------------------------------------------------------------------------
// Registration bitmask helpers
// ---------------------------------------------------------------------------

/// Bitmask field tracking which expedited commands a process has registered for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MembarrierRegistrationMask(u32);

impl MembarrierRegistrationMask {
    /// Construct an empty (no registrations) mask.
    pub const fn none() -> Self {
        Self(0)
    }

    /// Set the `bit` corresponding to a registration command.
    pub fn register(&mut self, bit: u32) {
        self.0 |= bit;
    }

    /// Return `true` if the given bit is registered.
    pub const fn has(&self, bit: u32) -> bool {
        self.0 & bit != 0
    }
}

// ---------------------------------------------------------------------------
// MembarrierProcessState — per-process membarrier state
// ---------------------------------------------------------------------------

/// Maximum number of processes tracked simultaneously.
const MAX_PROCS: usize = 128;

/// Per-process membarrier registration state.
#[derive(Debug, Clone, Copy)]
pub struct MembarrierProcessState {
    /// Process identifier.
    pub pid: u64,
    /// Set of expedited commands this process has registered for.
    pub registered: MembarrierRegistrationMask,
    /// Whether this slot is in use.
    pub active: bool,
}

impl MembarrierProcessState {
    /// Create an inactive slot.
    const fn empty() -> Self {
        Self {
            pid: 0,
            registered: MembarrierRegistrationMask::none(),
            active: false,
        }
    }
}

impl Default for MembarrierProcessState {
    fn default() -> Self {
        Self::empty()
    }
}

// ---------------------------------------------------------------------------
// SysMembarrierState — global subsystem state
// ---------------------------------------------------------------------------

/// Global membarrier subsystem state.
///
/// Tracks per-process registrations and accounting counters.  In a real
/// kernel this state would live in the scheduler subsystem; here it is
/// bundled as a testable unit.
pub struct SysMembarrierState {
    procs: [MembarrierProcessState; MAX_PROCS],
    count: usize,
    /// Number of `MEMBARRIER_CMD_GLOBAL` operations issued.
    pub global_count: u64,
    /// Number of expedited IPI operations issued.
    pub expedited_count: u64,
}

impl SysMembarrierState {
    /// Create a zeroed subsystem state.
    pub const fn new() -> Self {
        Self {
            procs: [const { MembarrierProcessState::empty() }; MAX_PROCS],
            count: 0,
            global_count: 0,
            expedited_count: 0,
        }
    }

    /// Return the number of active registrations.
    pub const fn registration_count(&self) -> usize {
        self.count
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn find_idx(&self, pid: u64) -> Option<usize> {
        self.procs.iter().position(|p| p.active && p.pid == pid)
    }

    fn find_or_alloc(&mut self, pid: u64) -> Result<usize> {
        if let Some(i) = self.find_idx(pid) {
            return Ok(i);
        }
        let slot = self
            .procs
            .iter()
            .position(|p| !p.active)
            .ok_or(Error::OutOfMemory)?;
        self.procs[slot] = MembarrierProcessState {
            pid,
            registered: MembarrierRegistrationMask::none(),
            active: true,
        };
        self.count += 1;
        Ok(slot)
    }

    fn is_registered(&self, pid: u64, bit: u32) -> bool {
        self.find_idx(pid)
            .map(|i| self.procs[i].registered.has(bit))
            .unwrap_or(false)
    }

    fn do_register(&mut self, pid: u64, bit: u32) -> Result<()> {
        let i = self.find_or_alloc(pid)?;
        self.procs[i].registered.register(bit);
        Ok(())
    }

    /// Deregister all membarrier state for `pid` (called on process exit).
    pub fn remove_pid(&mut self, pid: u64) {
        for p in self.procs.iter_mut() {
            if p.active && p.pid == pid {
                p.active = false;
                self.count = self.count.saturating_sub(1);
                return;
            }
        }
    }
}

impl Default for SysMembarrierState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// sys_membarrier_handler — main dispatcher
// ---------------------------------------------------------------------------

/// Handle the `membarrier(2)` syscall.
///
/// # Arguments
///
/// * `state`  — Mutable global membarrier state.
/// * `cmd`    — One of the `MEMBARRIER_CMD_*` constants.
/// * `flags`  — Command flags; currently only `MEMBARRIER_CMD_FLAG_CPU` is
///              defined (for rseq CPU targeting).
/// * `cpu_id` — CPU index for `MEMBARRIER_CMD_FLAG_CPU`; ignored otherwise.
/// * `pid`    — Calling process identifier.
///
/// # Returns
///
/// For `MEMBARRIER_CMD_QUERY`: bitmask of supported commands as `i32`.
/// For all other commands: `0` on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Unknown command, unknown flag bits, or
///   an expedited command was issued without prior registration.
/// * [`Error::OutOfMemory`]     — Registration table is full.
pub fn sys_membarrier_handler(
    state: &mut SysMembarrierState,
    cmd: i32,
    flags: u32,
    cpu_id: i32,
    pid: u64,
) -> Result<i32> {
    // Validate flags — only MEMBARRIER_CMD_FLAG_CPU is defined.
    // For most commands, flags must be zero.
    match cmd {
        MEMBARRIER_CMD_QUERY => {
            if flags != MEMBARRIER_CMD_FLAG_NONE {
                return Err(Error::InvalidArgument);
            }
            Ok(SUPPORTED_CMDS)
        }
        MEMBARRIER_CMD_GLOBAL => {
            if flags != MEMBARRIER_CMD_FLAG_NONE {
                return Err(Error::InvalidArgument);
            }
            // Issue a system-wide memory barrier.  In a real kernel this
            // calls schedule() on all CPUs to ensure all memory operations
            // are visible.  Here we track the count.
            state.global_count = state.global_count.saturating_add(1);
            Ok(0)
        }
        MEMBARRIER_CMD_GLOBAL_EXPEDITED => {
            if flags != MEMBARRIER_CMD_FLAG_NONE {
                return Err(Error::InvalidArgument);
            }
            if !state.is_registered(pid, MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED as u32) {
                return Err(Error::InvalidArgument);
            }
            state.expedited_count = state.expedited_count.saturating_add(1);
            Ok(0)
        }
        MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED => {
            if flags != MEMBARRIER_CMD_FLAG_NONE {
                return Err(Error::InvalidArgument);
            }
            state.do_register(pid, MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED as u32)?;
            Ok(0)
        }
        MEMBARRIER_CMD_PRIVATE_EXPEDITED => {
            if flags != MEMBARRIER_CMD_FLAG_NONE {
                return Err(Error::InvalidArgument);
            }
            if !state.is_registered(pid, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED as u32) {
                return Err(Error::InvalidArgument);
            }
            state.expedited_count = state.expedited_count.saturating_add(1);
            Ok(0)
        }
        MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED => {
            if flags != MEMBARRIER_CMD_FLAG_NONE {
                return Err(Error::InvalidArgument);
            }
            state.do_register(pid, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED as u32)?;
            Ok(0)
        }
        MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE => {
            if flags != MEMBARRIER_CMD_FLAG_NONE {
                return Err(Error::InvalidArgument);
            }
            if !state.is_registered(
                pid,
                MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE as u32,
            ) {
                return Err(Error::InvalidArgument);
            }
            state.expedited_count = state.expedited_count.saturating_add(1);
            Ok(0)
        }
        MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE => {
            if flags != MEMBARRIER_CMD_FLAG_NONE {
                return Err(Error::InvalidArgument);
            }
            state.do_register(
                pid,
                MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE as u32,
            )?;
            Ok(0)
        }
        MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ => {
            // rseq variant accepts the CPU flag.
            let unknown = flags & !FLAGS_MASK;
            if unknown != 0 {
                return Err(Error::InvalidArgument);
            }
            if !state.is_registered(pid, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ as u32) {
                return Err(Error::InvalidArgument);
            }
            // cpu_id is used when FLAGS_CPU is set; validate range (stub).
            if flags & MEMBARRIER_CMD_FLAG_CPU != 0 && cpu_id < 0 {
                return Err(Error::InvalidArgument);
            }
            state.expedited_count = state.expedited_count.saturating_add(1);
            Ok(0)
        }
        MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ => {
            if flags != MEMBARRIER_CMD_FLAG_NONE {
                return Err(Error::InvalidArgument);
            }
            state.do_register(pid, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ as u32)?;
            Ok(0)
        }
        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn new_state() -> SysMembarrierState {
        SysMembarrierState::new()
    }

    #[test]
    fn query_returns_supported_mask() {
        let mut s = new_state();
        let r = sys_membarrier_handler(&mut s, MEMBARRIER_CMD_QUERY, 0, 0, 1).unwrap();
        assert_eq!(r, SUPPORTED_CMDS);
    }

    #[test]
    fn query_rejects_nonzero_flags() {
        let mut s = new_state();
        assert_eq!(
            sys_membarrier_handler(&mut s, MEMBARRIER_CMD_QUERY, 1, 0, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn global_succeeds_without_registration() {
        let mut s = new_state();
        assert_eq!(
            sys_membarrier_handler(&mut s, MEMBARRIER_CMD_GLOBAL, 0, 0, 1),
            Ok(0)
        );
        assert_eq!(s.global_count, 1);
    }

    #[test]
    fn private_expedited_requires_registration() {
        let mut s = new_state();
        assert_eq!(
            sys_membarrier_handler(&mut s, MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn private_expedited_succeeds_after_registration() {
        let mut s = new_state();
        sys_membarrier_handler(&mut s, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0, 0, 1).unwrap();
        assert_eq!(
            sys_membarrier_handler(&mut s, MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0, 1),
            Ok(0)
        );
        assert_eq!(s.expedited_count, 1);
    }

    #[test]
    fn sync_core_requires_registration() {
        let mut s = new_state();
        assert_eq!(
            sys_membarrier_handler(&mut s, MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn rseq_with_cpu_flag_valid() {
        let mut s = new_state();
        sys_membarrier_handler(
            &mut s,
            MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ,
            0,
            0,
            1,
        )
        .unwrap();
        assert_eq!(
            sys_membarrier_handler(
                &mut s,
                MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ,
                MEMBARRIER_CMD_FLAG_CPU,
                2,
                1,
            ),
            Ok(0)
        );
    }

    #[test]
    fn rseq_with_negative_cpu_rejects() {
        let mut s = new_state();
        sys_membarrier_handler(
            &mut s,
            MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ,
            0,
            0,
            1,
        )
        .unwrap();
        assert_eq!(
            sys_membarrier_handler(
                &mut s,
                MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ,
                MEMBARRIER_CMD_FLAG_CPU,
                -1,
                1,
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn remove_pid_cleans_up() {
        let mut s = new_state();
        sys_membarrier_handler(&mut s, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0, 0, 42)
            .unwrap();
        assert_eq!(s.registration_count(), 1);
        s.remove_pid(42);
        assert_eq!(s.registration_count(), 0);
    }

    #[test]
    fn unknown_command_rejected() {
        let mut s = new_state();
        assert_eq!(
            sys_membarrier_handler(&mut s, 9999, 0, 0, 1),
            Err(Error::InvalidArgument)
        );
    }
}
