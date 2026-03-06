// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `membarrier(2)` — process-wide memory barrier syscall.
//!
//! The `membarrier` syscall issues memory barriers on a set of running
//! threads without requiring them to execute barrier instructions
//! themselves.  This is essential for efficient user-space RCU
//! implementations and lock-free data structures.
//!
//! # Commands
//!
//! | Command | Description |
//! |---------|-------------|
//! | `CMD_QUERY` | Query supported commands (returns bitmask) |
//! | `CMD_GLOBAL` | Issue a memory barrier on all threads |
//! | `CMD_GLOBAL_EXPEDITED` | Expedited global barrier (IPI-based) |
//! | `CMD_REGISTER_GLOBAL_EXPEDITED` | Register for expedited barriers |
//! | `CMD_PRIVATE_EXPEDITED` | Private expedited barrier (same process) |
//! | `CMD_REGISTER_PRIVATE_EXPEDITED` | Register for private expedited |
//! | `CMD_PRIVATE_EXPEDITED_SYNC_CORE` | Barrier + instruction cache sync |
//! | `CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE` | Register for sync-core |
//! | `CMD_PRIVATE_EXPEDITED_RSEQ` | Barrier for restartable sequences |
//! | `CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ` | Register for rseq barriers |
//!
//! # References
//!
//! - Linux: `kernel/sched/membarrier.c`
//! - man page: `membarrier(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Query which `membarrier` commands are supported.
///
/// Returns a bitmask of supported command bits.
pub const MEMBARRIER_CMD_QUERY: u32 = 0;

/// Issue a global memory barrier on all running threads.
///
/// This is the slowest command but requires no prior registration.
pub const MEMBARRIER_CMD_GLOBAL: u32 = 1 << 0;

/// Issue an expedited global memory barrier.
///
/// Faster than `CMD_GLOBAL` (uses IPIs), but requires prior
/// registration via [`MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED`].
pub const MEMBARRIER_CMD_GLOBAL_EXPEDITED: u32 = 1 << 1;

/// Register the current process for expedited global barriers.
pub const MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED: u32 = 1 << 2;

/// Issue an expedited memory barrier only within the current process.
///
/// Requires prior registration via
/// [`MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED`].
pub const MEMBARRIER_CMD_PRIVATE_EXPEDITED: u32 = 1 << 3;

/// Register the current process for private expedited barriers.
pub const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED: u32 = 1 << 4;

/// Issue an expedited barrier with instruction cache synchronization.
///
/// Ensures that instruction caches are flushed on all cores running
/// threads of this process. Requires registration via
/// [`MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE`].
pub const MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE: u32 = 1 << 5;

/// Register for private expedited sync-core barriers.
pub const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE: u32 = 1 << 6;

/// Issue an expedited barrier for restartable sequences (rseq).
///
/// Ensures rseq critical sections on remote threads are restarted.
/// Requires registration via
/// [`MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ`].
pub const MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ: u32 = 1 << 7;

/// Register for private expedited rseq barriers.
pub const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ: u32 = 1 << 8;

/// Bitmask of all known command bits (for validation).
const ALL_COMMANDS: u32 = MEMBARRIER_CMD_GLOBAL
    | MEMBARRIER_CMD_GLOBAL_EXPEDITED
    | MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED
    | MEMBARRIER_CMD_PRIVATE_EXPEDITED
    | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED
    | MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE
    | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE
    | MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ
    | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ;

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// No special flags.
pub const MEMBARRIER_CMD_FLAG_NONE: u32 = 0;

/// Target a specific CPU (for RSEQ commands).
pub const MEMBARRIER_CMD_FLAG_CPU: u32 = 1 << 0;

/// All valid flag bits.
const FLAGS_VALID: u32 = MEMBARRIER_CMD_FLAG_CPU;

// ---------------------------------------------------------------------------
// Maximum registrations
// ---------------------------------------------------------------------------

/// Maximum number of processes that can register for membarrier.
const MAX_REGISTRATIONS: usize = 64;

// ---------------------------------------------------------------------------
// MembarrierRegistration — per-process registration state
// ---------------------------------------------------------------------------

/// Registration state for a single process.
///
/// Tracks which membarrier commands this process has registered for.
#[derive(Debug, Clone, Copy)]
pub struct MembarrierRegistration {
    /// Process ID.
    pub pid: u64,
    /// Bitmask of registered command types.
    pub registered: u32,
    /// Whether this slot is active.
    pub active: bool,
}

impl MembarrierRegistration {
    /// Create an inactive registration slot.
    const fn new() -> Self {
        Self {
            pid: 0,
            registered: 0,
            active: false,
        }
    }

    /// Check if a specific command is registered.
    pub const fn is_registered(&self, cmd_bit: u32) -> bool {
        self.registered & cmd_bit != 0
    }
}

impl Default for MembarrierRegistration {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MembarrierState — global membarrier subsystem state
// ---------------------------------------------------------------------------

/// Global membarrier subsystem state.
///
/// Tracks per-process registrations and supports querying which
/// commands are available. In a real kernel, issuing a barrier would
/// send IPIs to the relevant CPUs; this stub records the operations
/// and tracks registration state.
pub struct MembarrierState {
    /// Per-process registration slots.
    registrations: [MembarrierRegistration; MAX_REGISTRATIONS],
    /// Number of active registrations.
    count: usize,
    /// Supported command bitmask (always all commands in this stub).
    supported: u32,
    /// Total number of barriers issued (for statistics).
    barriers_issued: u64,
    /// Total number of global barriers issued.
    global_barriers: u64,
    /// Total number of expedited barriers issued.
    expedited_barriers: u64,
    /// Total number of private barriers issued.
    private_barriers: u64,
}

impl MembarrierState {
    /// Create a new membarrier state with all commands supported.
    pub const fn new() -> Self {
        Self {
            registrations: [const { MembarrierRegistration::new() }; MAX_REGISTRATIONS],
            count: 0,
            supported: ALL_COMMANDS,
            barriers_issued: 0,
            global_barriers: 0,
            expedited_barriers: 0,
            private_barriers: 0,
        }
    }

    /// Return the number of active registrations.
    pub const fn registration_count(&self) -> usize {
        self.count
    }

    /// Return the total number of barriers issued.
    pub const fn barriers_issued(&self) -> u64 {
        self.barriers_issued
    }

    /// Return the number of global barriers issued.
    pub const fn global_barriers(&self) -> u64 {
        self.global_barriers
    }

    /// Return the number of expedited barriers issued.
    pub const fn expedited_barriers(&self) -> u64 {
        self.expedited_barriers
    }

    /// Return the number of private barriers issued.
    pub const fn private_barriers(&self) -> u64 {
        self.private_barriers
    }

    /// Return the bitmask of supported commands.
    pub const fn supported_commands(&self) -> u32 {
        self.supported
    }

    // ---------------------------------------------------------------
    // Registration management
    // ---------------------------------------------------------------

    /// Find or create a registration slot for the given PID.
    fn find_or_create(&mut self, pid: u64) -> Result<usize> {
        // First, look for an existing registration.
        for i in 0..self.registrations.len() {
            if self.registrations[i].active && self.registrations[i].pid == pid {
                return Ok(i);
            }
        }
        // Allocate a new slot.
        for i in 0..self.registrations.len() {
            if !self.registrations[i].active {
                self.registrations[i].pid = pid;
                self.registrations[i].registered = 0;
                self.registrations[i].active = true;
                self.count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find a registration for the given PID.
    fn find_registration(&self, pid: u64) -> Option<&MembarrierRegistration> {
        self.registrations.iter().find(|r| r.active && r.pid == pid)
    }

    /// Register a process for a specific command type.
    fn register(&mut self, pid: u64, cmd_bit: u32) -> Result<()> {
        let idx = self.find_or_create(pid)?;
        self.registrations[idx].registered |= cmd_bit;
        Ok(())
    }

    /// Check if a process is registered for a specific command type.
    fn is_registered(&self, pid: u64, cmd_bit: u32) -> bool {
        self.find_registration(pid)
            .map(|r| r.is_registered(cmd_bit))
            .unwrap_or(false)
    }

    /// Remove all registrations for a process.
    ///
    /// Called during process cleanup.
    pub fn unregister_pid(&mut self, pid: u64) {
        for reg in self.registrations.iter_mut() {
            if reg.active && reg.pid == pid {
                reg.active = false;
                reg.registered = 0;
                self.count = self.count.saturating_sub(1);
                return;
            }
        }
    }

    // ---------------------------------------------------------------
    // Command dispatch
    // ---------------------------------------------------------------

    /// Issue a global memory barrier.
    ///
    /// In a real kernel, this would serialize memory operations across
    /// all CPUs. The stub tracks the operation count.
    fn do_global_barrier(&mut self) -> Result<()> {
        self.barriers_issued = self.barriers_issued.saturating_add(1);
        self.global_barriers = self.global_barriers.saturating_add(1);
        // Stub: in the real kernel, this would issue sys_membarrier()
        // which serializes all running threads via schedule().
        Ok(())
    }

    /// Issue an expedited global memory barrier.
    ///
    /// Requires prior registration. In a real kernel, this sends IPIs
    /// to all CPUs running threads of registered processes.
    fn do_global_expedited(&mut self, pid: u64) -> Result<()> {
        if !self.is_registered(pid, MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED) {
            return Err(Error::InvalidArgument);
        }
        self.barriers_issued = self.barriers_issued.saturating_add(1);
        self.expedited_barriers = self.expedited_barriers.saturating_add(1);
        Ok(())
    }

    /// Issue a private expedited memory barrier.
    ///
    /// Only affects threads within the calling process. Requires
    /// prior registration.
    fn do_private_expedited(&mut self, pid: u64) -> Result<()> {
        if !self.is_registered(pid, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED) {
            return Err(Error::InvalidArgument);
        }
        self.barriers_issued = self.barriers_issued.saturating_add(1);
        self.private_barriers = self.private_barriers.saturating_add(1);
        Ok(())
    }

    /// Issue a private expedited sync-core barrier.
    ///
    /// Ensures instruction caches are synchronized. Requires prior
    /// registration.
    fn do_private_expedited_sync_core(&mut self, pid: u64) -> Result<()> {
        if !self.is_registered(pid, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE) {
            return Err(Error::InvalidArgument);
        }
        self.barriers_issued = self.barriers_issued.saturating_add(1);
        self.private_barriers = self.private_barriers.saturating_add(1);
        Ok(())
    }

    /// Issue a private expedited rseq barrier.
    ///
    /// Restarts restartable sequences on remote threads. Requires
    /// prior registration.
    fn do_private_expedited_rseq(&mut self, pid: u64, flags: u32) -> Result<()> {
        if !self.is_registered(pid, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ) {
            return Err(Error::InvalidArgument);
        }
        // CPU targeting flag is accepted but not acted upon in stub.
        if (flags & !FLAGS_VALID) != 0 {
            return Err(Error::InvalidArgument);
        }
        self.barriers_issued = self.barriers_issued.saturating_add(1);
        self.private_barriers = self.private_barriers.saturating_add(1);
        Ok(())
    }
}

impl Default for MembarrierState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// sys_membarrier — the main syscall handler
// ---------------------------------------------------------------------------

/// Handler for `membarrier(2)`.
///
/// Dispatches the given command with the specified flags for the
/// calling process identified by `pid`.
///
/// # Arguments
///
/// * `state` — Global membarrier subsystem state.
/// * `cmd`   — One of the `MEMBARRIER_CMD_*` constants.
/// * `flags` — Command flags (currently only `MEMBARRIER_CMD_FLAG_CPU`
///             is defined, for RSEQ targeting).
/// * `pid`   — Calling process ID.
///
/// # Returns
///
/// For `CMD_QUERY`, returns the bitmask of supported commands.
/// For all other commands, returns 0 on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Unknown command, invalid flags, or
///   command requires registration that has not been performed.
pub fn sys_membarrier(state: &mut MembarrierState, cmd: u32, flags: u32, pid: u64) -> Result<u32> {
    match cmd {
        MEMBARRIER_CMD_QUERY => {
            // Query: flags must be zero.
            if flags != 0 {
                return Err(Error::InvalidArgument);
            }
            Ok(state.supported_commands())
        }
        MEMBARRIER_CMD_GLOBAL => {
            if flags != 0 {
                return Err(Error::InvalidArgument);
            }
            state.do_global_barrier()?;
            Ok(0)
        }
        MEMBARRIER_CMD_GLOBAL_EXPEDITED => {
            if flags != 0 {
                return Err(Error::InvalidArgument);
            }
            state.do_global_expedited(pid)?;
            Ok(0)
        }
        MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED => {
            if flags != 0 {
                return Err(Error::InvalidArgument);
            }
            state.register(pid, MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED)?;
            Ok(0)
        }
        MEMBARRIER_CMD_PRIVATE_EXPEDITED => {
            if flags != 0 {
                return Err(Error::InvalidArgument);
            }
            state.do_private_expedited(pid)?;
            Ok(0)
        }
        MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED => {
            if flags != 0 {
                return Err(Error::InvalidArgument);
            }
            state.register(pid, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED)?;
            Ok(0)
        }
        MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE => {
            if flags != 0 {
                return Err(Error::InvalidArgument);
            }
            state.do_private_expedited_sync_core(pid)?;
            Ok(0)
        }
        MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE => {
            if flags != 0 {
                return Err(Error::InvalidArgument);
            }
            state.register(pid, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE)?;
            Ok(0)
        }
        MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ => {
            state.do_private_expedited_rseq(pid, flags)?;
            Ok(0)
        }
        MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ => {
            if flags != 0 {
                return Err(Error::InvalidArgument);
            }
            state.register(pid, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ)?;
            Ok(0)
        }
        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_returns_all_commands() {
        let mut s = MembarrierState::new();
        let r = sys_membarrier(&mut s, MEMBARRIER_CMD_QUERY, 0, 1);
        assert_eq!(r, Ok(ALL_COMMANDS));
    }

    #[test]
    fn query_with_flags_fails() {
        let mut s = MembarrierState::new();
        let r = sys_membarrier(&mut s, MEMBARRIER_CMD_QUERY, 1, 1);
        assert_eq!(r, Err(Error::InvalidArgument));
    }

    #[test]
    fn global_barrier_succeeds() {
        let mut s = MembarrierState::new();
        let r = sys_membarrier(&mut s, MEMBARRIER_CMD_GLOBAL, 0, 1);
        assert_eq!(r, Ok(0));
        assert_eq!(s.barriers_issued(), 1);
        assert_eq!(s.global_barriers(), 1);
    }

    #[test]
    fn global_expedited_requires_registration() {
        let mut s = MembarrierState::new();
        // Without registration, should fail.
        let r = sys_membarrier(&mut s, MEMBARRIER_CMD_GLOBAL_EXPEDITED, 0, 1);
        assert_eq!(r, Err(Error::InvalidArgument));
    }

    #[test]
    fn global_expedited_succeeds_after_registration() {
        let mut s = MembarrierState::new();
        let _ = sys_membarrier(&mut s, MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED, 0, 1);
        let r = sys_membarrier(&mut s, MEMBARRIER_CMD_GLOBAL_EXPEDITED, 0, 1);
        assert_eq!(r, Ok(0));
        assert_eq!(s.expedited_barriers(), 1);
    }

    #[test]
    fn private_expedited_requires_registration() {
        let mut s = MembarrierState::new();
        let r = sys_membarrier(&mut s, MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 1);
        assert_eq!(r, Err(Error::InvalidArgument));
    }

    #[test]
    fn private_expedited_succeeds_after_registration() {
        let mut s = MembarrierState::new();
        let _ = sys_membarrier(&mut s, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0, 1);
        let r = sys_membarrier(&mut s, MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 1);
        assert_eq!(r, Ok(0));
        assert_eq!(s.private_barriers(), 1);
    }

    #[test]
    fn sync_core_requires_registration() {
        let mut s = MembarrierState::new();
        let r = sys_membarrier(&mut s, MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 1);
        assert_eq!(r, Err(Error::InvalidArgument));
    }

    #[test]
    fn sync_core_succeeds_after_registration() {
        let mut s = MembarrierState::new();
        let _ = sys_membarrier(
            &mut s,
            MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE,
            0,
            1,
        );
        let r = sys_membarrier(&mut s, MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 1);
        assert_eq!(r, Ok(0));
    }

    #[test]
    fn rseq_requires_registration() {
        let mut s = MembarrierState::new();
        let r = sys_membarrier(&mut s, MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ, 0, 1);
        assert_eq!(r, Err(Error::InvalidArgument));
    }

    #[test]
    fn rseq_succeeds_after_registration() {
        let mut s = MembarrierState::new();
        let _ = sys_membarrier(&mut s, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ, 0, 1);
        let r = sys_membarrier(&mut s, MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ, 0, 1);
        assert_eq!(r, Ok(0));
    }

    #[test]
    fn rseq_with_cpu_flag() {
        let mut s = MembarrierState::new();
        let _ = sys_membarrier(&mut s, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ, 0, 1);
        let r = sys_membarrier(
            &mut s,
            MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ,
            MEMBARRIER_CMD_FLAG_CPU,
            1,
        );
        assert_eq!(r, Ok(0));
    }

    #[test]
    fn unknown_command_rejected() {
        let mut s = MembarrierState::new();
        let r = sys_membarrier(&mut s, 0xFFFF, 0, 1);
        assert_eq!(r, Err(Error::InvalidArgument));
    }

    #[test]
    fn unregister_pid_removes_registration() {
        let mut s = MembarrierState::new();
        let _ = sys_membarrier(&mut s, MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED, 0, 42);
        assert_eq!(s.registration_count(), 1);
        s.unregister_pid(42);
        assert_eq!(s.registration_count(), 0);
        // After unregister, expedited should fail.
        let r = sys_membarrier(&mut s, MEMBARRIER_CMD_GLOBAL_EXPEDITED, 0, 42);
        assert_eq!(r, Err(Error::InvalidArgument));
    }

    #[test]
    fn multiple_registrations_same_pid() {
        let mut s = MembarrierState::new();
        let _ = sys_membarrier(&mut s, MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED, 0, 1);
        let _ = sys_membarrier(&mut s, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0, 1);
        // Should reuse the same registration slot.
        assert_eq!(s.registration_count(), 1);
        // Both commands should work.
        assert_eq!(
            sys_membarrier(&mut s, MEMBARRIER_CMD_GLOBAL_EXPEDITED, 0, 1),
            Ok(0)
        );
        assert_eq!(
            sys_membarrier(&mut s, MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 1),
            Ok(0)
        );
    }

    #[test]
    fn registration_default() {
        let r = MembarrierRegistration::default();
        assert!(!r.active);
        assert_eq!(r.registered, 0);
    }
}
