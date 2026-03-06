// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `membarrier(2)` syscall — process-wide memory barriers without
//! per-thread instruction overhead.
//!
//! The `membarrier` syscall allows a process to issue memory barriers
//! across a set of running threads without requiring each thread to
//! execute an explicit barrier instruction.  This is the foundation
//! for efficient user-space RCU, lock-free data structures, and JIT
//! code patching.
//!
//! # Command Overview
//!
//! | Command | Value | Registration required | Description |
//! |---------|-------|----------------------|-------------|
//! | `Query` | 0 | No | Query supported commands |
//! | `Global` | 1 | No | Full global barrier |
//! | `GlobalExpedited` | 2 | Yes | IPI-based global barrier |
//! | `PrivateExpedited` | 8 | Yes | Barrier within process |
//! | `PrivateExpeditedSyncCore` | 32 | Yes | Barrier + icache sync |
//! | `PrivateExpeditedRseq` | 128 | Yes | Barrier for rseq |
//!
//! # Flag Bits
//!
//! | Flag | Value | Applies to | Description |
//! |------|-------|-----------|-------------|
//! | `CPU` | 1 | RSEQ only | Target a specific CPU |
//!
//! # References
//!
//! - Linux: `kernel/sched/membarrier.c`
//! - `man membarrier(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// MembarrierCmd — command enumeration
// ---------------------------------------------------------------------------

/// Commands for the `membarrier(2)` syscall.
///
/// Each variant corresponds to a single `MEMBARRIER_CMD_*` constant.
/// Registration commands enable the corresponding barrier command for
/// the calling process.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembarrierCmd {
    /// Query the set of supported commands (returns bitmask).
    Query = 0,
    /// Issue a full memory barrier on every running thread.
    ///
    /// Slowest but requires no prior registration.
    Global = 1,
    /// Issue an expedited (IPI-based) global memory barrier.
    ///
    /// Requires prior `RegisterGlobalExpedited`.
    GlobalExpedited = 2,
    /// Register the process for `GlobalExpedited` barriers.
    RegisterGlobalExpedited = 4,
    /// Issue an expedited barrier within the calling process only.
    ///
    /// Requires prior `RegisterPrivateExpedited`.
    PrivateExpedited = 8,
    /// Register the process for `PrivateExpedited` barriers.
    RegisterPrivateExpedited = 16,
    /// Issue a private expedited barrier with instruction-cache sync.
    ///
    /// Ensures that modified code pages are visible on all cores
    /// running threads of this process.
    /// Requires prior `RegisterPrivateExpeditedSyncCore`.
    PrivateExpeditedSyncCore = 32,
    /// Register the process for `PrivateExpeditedSyncCore` barriers.
    RegisterPrivateExpeditedSyncCore = 64,
    /// Issue a private expedited barrier for restartable sequences.
    ///
    /// Forces remote threads to restart any in-flight rseq critical
    /// section.  Requires prior `RegisterPrivateExpeditedRseq`.
    PrivateExpeditedRseq = 128,
    /// Register the process for `PrivateExpeditedRseq` barriers.
    RegisterPrivateExpeditedRseq = 256,
}

impl MembarrierCmd {
    /// Construct from a raw command value.
    ///
    /// Returns `None` for unrecognised values.
    pub fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::Query),
            1 => Some(Self::Global),
            2 => Some(Self::GlobalExpedited),
            4 => Some(Self::RegisterGlobalExpedited),
            8 => Some(Self::PrivateExpedited),
            16 => Some(Self::RegisterPrivateExpedited),
            32 => Some(Self::PrivateExpeditedSyncCore),
            64 => Some(Self::RegisterPrivateExpeditedSyncCore),
            128 => Some(Self::PrivateExpeditedRseq),
            256 => Some(Self::RegisterPrivateExpeditedRseq),
            _ => None,
        }
    }

    /// Return the raw numeric value.
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// Return `true` if this is a registration command.
    pub const fn is_registration(self) -> bool {
        matches!(
            self,
            Self::RegisterGlobalExpedited
                | Self::RegisterPrivateExpedited
                | Self::RegisterPrivateExpeditedSyncCore
                | Self::RegisterPrivateExpeditedRseq
        )
    }

    /// For a barrier command, return the corresponding registration
    /// command that must have been issued first.  Returns `None` for
    /// commands that do not require registration.
    pub const fn required_registration(self) -> Option<Self> {
        match self {
            Self::GlobalExpedited => Some(Self::RegisterGlobalExpedited),
            Self::PrivateExpedited => Some(Self::RegisterPrivateExpedited),
            Self::PrivateExpeditedSyncCore => Some(Self::RegisterPrivateExpeditedSyncCore),
            Self::PrivateExpeditedRseq => Some(Self::RegisterPrivateExpeditedRseq),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// MembarrierFlags
// ---------------------------------------------------------------------------

/// Flags for the `membarrier(2)` syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MembarrierFlags(u32);

impl MembarrierFlags {
    /// No special flags.
    pub const NONE: Self = Self(0);

    /// Target a specific CPU (valid only with RSEQ commands).
    pub const CPU: Self = Self(1);

    /// All valid flag bits combined.
    const VALID_MASK: u32 = 1;

    /// Construct from a raw flags value, validating all bits.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if unknown bits are set.
    pub fn from_raw(raw: u32) -> Result<Self> {
        if raw & !Self::VALID_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Return the raw numeric value.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Return `true` if the CPU-targeting flag is set.
    pub const fn has_cpu(self) -> bool {
        self.0 & 1 != 0
    }

    /// Return `true` if no flags are set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl Default for MembarrierFlags {
    fn default() -> Self {
        Self::NONE
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of per-process registrations tracked.
const MAX_PROCESSES: usize = 128;

/// Bitmask of all supported (non-query) commands.
const ALL_SUPPORTED: u32 = MembarrierCmd::Global.as_u32()
    | MembarrierCmd::GlobalExpedited.as_u32()
    | MembarrierCmd::RegisterGlobalExpedited.as_u32()
    | MembarrierCmd::PrivateExpedited.as_u32()
    | MembarrierCmd::RegisterPrivateExpedited.as_u32()
    | MembarrierCmd::PrivateExpeditedSyncCore.as_u32()
    | MembarrierCmd::RegisterPrivateExpeditedSyncCore.as_u32()
    | MembarrierCmd::PrivateExpeditedRseq.as_u32()
    | MembarrierCmd::RegisterPrivateExpeditedRseq.as_u32();

// ---------------------------------------------------------------------------
// ProcessRegistration — per-process registration record
// ---------------------------------------------------------------------------

/// Per-process registration record for membarrier.
///
/// Tracks which barrier commands this process has registered for.
#[derive(Debug, Clone, Copy)]
pub struct ProcessRegistration {
    /// Process ID.
    pid: u64,
    /// Bitmask of registered command bits.
    registered: u32,
    /// Whether this slot is active.
    active: bool,
}

impl ProcessRegistration {
    /// Create an inactive slot.
    const fn empty() -> Self {
        Self {
            pid: 0,
            registered: 0,
            active: false,
        }
    }

    /// Return the PID of this registration.
    pub const fn pid(&self) -> u64 {
        self.pid
    }

    /// Return the bitmask of registered commands.
    pub const fn registered_mask(&self) -> u32 {
        self.registered
    }

    /// Check if a specific command bit is registered.
    pub const fn has_registration(&self, cmd_bit: u32) -> bool {
        self.registered & cmd_bit != 0
    }
}

impl Default for ProcessRegistration {
    fn default() -> Self {
        Self::empty()
    }
}

// ---------------------------------------------------------------------------
// MembarrierState — global subsystem state
// ---------------------------------------------------------------------------

/// Global state for the membarrier subsystem.
///
/// Tracks per-process registrations and barrier issuance statistics.
/// In a production kernel the barrier operations would send IPIs to
/// relevant CPUs; this implementation records operations and validates
/// registration requirements.
pub struct MembarrierState {
    /// Per-process registration slots.
    procs: [ProcessRegistration; MAX_PROCESSES],
    /// Number of active registrations.
    active_count: usize,
    /// Bitmask of supported commands.
    supported: u32,
    /// Total barriers issued (all types).
    total_barriers: u64,
    /// Global barriers issued.
    global_count: u64,
    /// Expedited barriers issued (global + private).
    expedited_count: u64,
    /// Sync-core barriers issued.
    sync_core_count: u64,
    /// Rseq barriers issued.
    rseq_count: u64,
}

impl MembarrierState {
    /// Create a new state instance with all commands supported.
    pub const fn new() -> Self {
        Self {
            procs: [const { ProcessRegistration::empty() }; MAX_PROCESSES],
            active_count: 0,
            supported: ALL_SUPPORTED,
            total_barriers: 0,
            global_count: 0,
            expedited_count: 0,
            sync_core_count: 0,
            rseq_count: 0,
        }
    }

    /// Return the number of active registrations.
    pub const fn active_count(&self) -> usize {
        self.active_count
    }

    /// Return the total barrier count.
    pub const fn total_barriers(&self) -> u64 {
        self.total_barriers
    }

    /// Return the global barrier count.
    pub const fn global_count(&self) -> u64 {
        self.global_count
    }

    /// Return the expedited barrier count.
    pub const fn expedited_count(&self) -> u64 {
        self.expedited_count
    }

    /// Return the sync-core barrier count.
    pub const fn sync_core_count(&self) -> u64 {
        self.sync_core_count
    }

    /// Return the rseq barrier count.
    pub const fn rseq_count(&self) -> u64 {
        self.rseq_count
    }

    /// Return the bitmask of supported commands.
    pub const fn supported(&self) -> u32 {
        self.supported
    }

    // ----- Registration management -----

    /// Find the registration slot for `pid`, or allocate a new one.
    fn find_or_alloc(&mut self, pid: u64) -> Result<usize> {
        // Look for an existing active registration.
        for i in 0..self.procs.len() {
            if self.procs[i].active && self.procs[i].pid == pid {
                return Ok(i);
            }
        }
        // Allocate a free slot.
        for i in 0..self.procs.len() {
            if !self.procs[i].active {
                self.procs[i] = ProcessRegistration {
                    pid,
                    registered: 0,
                    active: true,
                };
                self.active_count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Check whether `pid` has registered for `cmd_bit`.
    fn is_registered(&self, pid: u64, cmd_bit: u32) -> bool {
        self.procs
            .iter()
            .any(|r| r.active && r.pid == pid && r.has_registration(cmd_bit))
    }

    /// Register `pid` for a specific command bit.
    fn do_register(&mut self, pid: u64, cmd_bit: u32) -> Result<()> {
        let idx = self.find_or_alloc(pid)?;
        self.procs[idx].registered |= cmd_bit;
        Ok(())
    }

    /// Remove all registrations for `pid`.
    ///
    /// Called during process cleanup / exit.
    pub fn remove_process(&mut self, pid: u64) {
        for slot in self.procs.iter_mut() {
            if slot.active && slot.pid == pid {
                slot.active = false;
                slot.registered = 0;
                self.active_count = self.active_count.saturating_sub(1);
                return;
            }
        }
    }

    /// Look up the registration record for `pid`.
    pub fn find_registration(&self, pid: u64) -> Option<&ProcessRegistration> {
        self.procs.iter().find(|r| r.active && r.pid == pid)
    }

    // ----- Barrier issuance -----

    /// Issue a global memory barrier.
    fn issue_global(&mut self) {
        self.total_barriers = self.total_barriers.saturating_add(1);
        self.global_count = self.global_count.saturating_add(1);
        // Stub: a real kernel would call `smp_mb()` on all CPUs via
        // synchronize_rcu() or schedule on each CPU.
    }

    /// Issue an expedited global barrier.
    fn issue_global_expedited(&mut self, pid: u64) -> Result<()> {
        let reg_cmd = MembarrierCmd::RegisterGlobalExpedited;
        if !self.is_registered(pid, reg_cmd.as_u32()) {
            return Err(Error::InvalidArgument);
        }
        self.total_barriers = self.total_barriers.saturating_add(1);
        self.expedited_count = self.expedited_count.saturating_add(1);
        Ok(())
    }

    /// Issue a private expedited barrier.
    fn issue_private_expedited(&mut self, pid: u64) -> Result<()> {
        let reg_cmd = MembarrierCmd::RegisterPrivateExpedited;
        if !self.is_registered(pid, reg_cmd.as_u32()) {
            return Err(Error::InvalidArgument);
        }
        self.total_barriers = self.total_barriers.saturating_add(1);
        self.expedited_count = self.expedited_count.saturating_add(1);
        Ok(())
    }

    /// Issue a private expedited sync-core barrier.
    fn issue_sync_core(&mut self, pid: u64) -> Result<()> {
        let reg_cmd = MembarrierCmd::RegisterPrivateExpeditedSyncCore;
        if !self.is_registered(pid, reg_cmd.as_u32()) {
            return Err(Error::InvalidArgument);
        }
        self.total_barriers = self.total_barriers.saturating_add(1);
        self.sync_core_count = self.sync_core_count.saturating_add(1);
        Ok(())
    }

    /// Issue a private expedited rseq barrier.
    fn issue_rseq(&mut self, pid: u64, flags: MembarrierFlags) -> Result<()> {
        let reg_cmd = MembarrierCmd::RegisterPrivateExpeditedRseq;
        if !self.is_registered(pid, reg_cmd.as_u32()) {
            return Err(Error::InvalidArgument);
        }
        // The CPU flag is accepted but not acted upon in the stub.
        let _ = flags.has_cpu();
        self.total_barriers = self.total_barriers.saturating_add(1);
        self.rseq_count = self.rseq_count.saturating_add(1);
        Ok(())
    }
}

impl Default for MembarrierState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// do_membarrier — main syscall dispatcher
// ---------------------------------------------------------------------------

/// Handler for `membarrier(2)`.
///
/// Dispatches the given command with the specified flags for the
/// calling process.
///
/// # Arguments
///
/// * `state` - Global membarrier subsystem state.
/// * `cmd`   - Raw command value (one of the `MembarrierCmd` variants).
/// * `flags` - Raw flags value.
/// * `pid`   - Calling process ID.
///
/// # Returns
///
/// * For `Query`: a bitmask of supported commands.
/// * For barrier/registration commands: 0 on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] - Unknown command, invalid flags,
///   non-zero flags where not allowed, or missing registration.
/// * [`Error::OutOfMemory`]     - Registration table is full.
pub fn do_membarrier(state: &mut MembarrierState, cmd: u32, flags: u32, pid: u64) -> Result<u32> {
    let command = MembarrierCmd::from_raw(cmd).ok_or(Error::InvalidArgument)?;
    let mflags = MembarrierFlags::from_raw(flags)?;

    // For most commands, flags must be zero.
    let require_zero_flags = !matches!(command, MembarrierCmd::PrivateExpeditedRseq);
    if require_zero_flags && !mflags.is_empty() {
        return Err(Error::InvalidArgument);
    }

    match command {
        MembarrierCmd::Query => Ok(state.supported()),
        MembarrierCmd::Global => {
            state.issue_global();
            Ok(0)
        }
        MembarrierCmd::GlobalExpedited => {
            state.issue_global_expedited(pid)?;
            Ok(0)
        }
        MembarrierCmd::RegisterGlobalExpedited => {
            let reg = MembarrierCmd::RegisterGlobalExpedited;
            state.do_register(pid, reg.as_u32())?;
            Ok(0)
        }
        MembarrierCmd::PrivateExpedited => {
            state.issue_private_expedited(pid)?;
            Ok(0)
        }
        MembarrierCmd::RegisterPrivateExpedited => {
            let reg = MembarrierCmd::RegisterPrivateExpedited;
            state.do_register(pid, reg.as_u32())?;
            Ok(0)
        }
        MembarrierCmd::PrivateExpeditedSyncCore => {
            state.issue_sync_core(pid)?;
            Ok(0)
        }
        MembarrierCmd::RegisterPrivateExpeditedSyncCore => {
            let reg = MembarrierCmd::RegisterPrivateExpeditedSyncCore;
            state.do_register(pid, reg.as_u32())?;
            Ok(0)
        }
        MembarrierCmd::PrivateExpeditedRseq => {
            state.issue_rseq(pid, mflags)?;
            Ok(0)
        }
        MembarrierCmd::RegisterPrivateExpeditedRseq => {
            let reg = MembarrierCmd::RegisterPrivateExpeditedRseq;
            state.do_register(pid, reg.as_u32())?;
            Ok(0)
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- MembarrierCmd ---

    #[test]
    fn cmd_from_valid() {
        assert_eq!(MembarrierCmd::from_raw(0), Some(MembarrierCmd::Query));
        assert_eq!(MembarrierCmd::from_raw(1), Some(MembarrierCmd::Global));
        assert_eq!(
            MembarrierCmd::from_raw(128),
            Some(MembarrierCmd::PrivateExpeditedRseq)
        );
    }

    #[test]
    fn cmd_from_invalid() {
        assert!(MembarrierCmd::from_raw(0xFFFF).is_none());
        assert!(MembarrierCmd::from_raw(3).is_none());
    }

    #[test]
    fn cmd_is_registration() {
        assert!(MembarrierCmd::RegisterGlobalExpedited.is_registration());
        assert!(MembarrierCmd::RegisterPrivateExpedited.is_registration());
        assert!(!MembarrierCmd::Global.is_registration());
        assert!(!MembarrierCmd::Query.is_registration());
    }

    #[test]
    fn cmd_required_registration() {
        assert_eq!(
            MembarrierCmd::GlobalExpedited.required_registration(),
            Some(MembarrierCmd::RegisterGlobalExpedited)
        );
        assert_eq!(MembarrierCmd::Global.required_registration(), None);
        assert_eq!(MembarrierCmd::Query.required_registration(), None);
    }

    // --- MembarrierFlags ---

    #[test]
    fn flags_valid() {
        let f = MembarrierFlags::from_raw(0).unwrap();
        assert!(f.is_empty());
        assert!(!f.has_cpu());

        let f = MembarrierFlags::from_raw(1).unwrap();
        assert!(!f.is_empty());
        assert!(f.has_cpu());
    }

    #[test]
    fn flags_invalid() {
        assert_eq!(
            MembarrierFlags::from_raw(0x100),
            Err(Error::InvalidArgument)
        );
    }

    // --- Query ---

    #[test]
    fn query_returns_supported() {
        let mut s = MembarrierState::new();
        let r = do_membarrier(&mut s, 0, 0, 1);
        assert_eq!(r, Ok(ALL_SUPPORTED));
    }

    #[test]
    fn query_with_flags_fails() {
        let mut s = MembarrierState::new();
        assert_eq!(do_membarrier(&mut s, 0, 1, 1), Err(Error::InvalidArgument));
    }

    // --- Global barrier ---

    #[test]
    fn global_barrier_no_registration_needed() {
        let mut s = MembarrierState::new();
        assert_eq!(do_membarrier(&mut s, 1, 0, 1), Ok(0));
        assert_eq!(s.total_barriers(), 1);
        assert_eq!(s.global_count(), 1);
    }

    // --- Global expedited ---

    #[test]
    fn global_expedited_requires_registration() {
        let mut s = MembarrierState::new();
        assert_eq!(do_membarrier(&mut s, 2, 0, 1), Err(Error::InvalidArgument));
    }

    #[test]
    fn global_expedited_after_registration() {
        let mut s = MembarrierState::new();
        do_membarrier(&mut s, 4, 0, 1).unwrap(); // register
        assert_eq!(do_membarrier(&mut s, 2, 0, 1), Ok(0));
        assert_eq!(s.expedited_count(), 1);
    }

    // --- Private expedited ---

    #[test]
    fn private_expedited_requires_registration() {
        let mut s = MembarrierState::new();
        assert_eq!(do_membarrier(&mut s, 8, 0, 1), Err(Error::InvalidArgument));
    }

    #[test]
    fn private_expedited_after_registration() {
        let mut s = MembarrierState::new();
        do_membarrier(&mut s, 16, 0, 1).unwrap(); // register
        assert_eq!(do_membarrier(&mut s, 8, 0, 1), Ok(0));
        assert_eq!(s.expedited_count(), 1);
    }

    // --- Sync core ---

    #[test]
    fn sync_core_requires_registration() {
        let mut s = MembarrierState::new();
        assert_eq!(do_membarrier(&mut s, 32, 0, 1), Err(Error::InvalidArgument));
    }

    #[test]
    fn sync_core_after_registration() {
        let mut s = MembarrierState::new();
        do_membarrier(&mut s, 64, 0, 1).unwrap(); // register
        assert_eq!(do_membarrier(&mut s, 32, 0, 1), Ok(0));
        assert_eq!(s.sync_core_count(), 1);
    }

    // --- Rseq ---

    #[test]
    fn rseq_requires_registration() {
        let mut s = MembarrierState::new();
        assert_eq!(
            do_membarrier(&mut s, 128, 0, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn rseq_after_registration() {
        let mut s = MembarrierState::new();
        do_membarrier(&mut s, 256, 0, 1).unwrap(); // register
        assert_eq!(do_membarrier(&mut s, 128, 0, 1), Ok(0));
        assert_eq!(s.rseq_count(), 1);
    }

    #[test]
    fn rseq_with_cpu_flag() {
        let mut s = MembarrierState::new();
        do_membarrier(&mut s, 256, 0, 1).unwrap(); // register
        assert_eq!(do_membarrier(&mut s, 128, 1, 1), Ok(0));
        assert_eq!(s.rseq_count(), 1);
    }

    // --- Unknown command ---

    #[test]
    fn unknown_command_rejected() {
        let mut s = MembarrierState::new();
        assert_eq!(
            do_membarrier(&mut s, 0xDEAD, 0, 1),
            Err(Error::InvalidArgument)
        );
    }

    // --- Process cleanup ---

    #[test]
    fn remove_process_clears_registration() {
        let mut s = MembarrierState::new();
        do_membarrier(&mut s, 4, 0, 42).unwrap(); // register
        assert_eq!(s.active_count(), 1);
        s.remove_process(42);
        assert_eq!(s.active_count(), 0);
        // Barrier should now fail.
        assert_eq!(do_membarrier(&mut s, 2, 0, 42), Err(Error::InvalidArgument));
    }

    // --- Multiple registrations reuse slot ---

    #[test]
    fn multiple_registrations_same_pid() {
        let mut s = MembarrierState::new();
        do_membarrier(&mut s, 4, 0, 1).unwrap(); // register global exp
        do_membarrier(&mut s, 16, 0, 1).unwrap(); // register private exp
        // Only one slot should be used.
        assert_eq!(s.active_count(), 1);
        // Both barriers should work.
        assert_eq!(do_membarrier(&mut s, 2, 0, 1), Ok(0));
        assert_eq!(do_membarrier(&mut s, 8, 0, 1), Ok(0));
    }

    // --- Registration record lookup ---

    #[test]
    fn find_registration_after_register() {
        let mut s = MembarrierState::new();
        do_membarrier(&mut s, 4, 0, 77).unwrap();
        let reg = s.find_registration(77).unwrap();
        assert_eq!(reg.pid(), 77);
        assert!(reg.has_registration(MembarrierCmd::RegisterGlobalExpedited.as_u32()));
    }

    #[test]
    fn find_registration_not_found() {
        let s = MembarrierState::new();
        assert!(s.find_registration(99).is_none());
    }

    // --- Default ---

    #[test]
    fn default_state_is_empty() {
        let s = MembarrierState::default();
        assert_eq!(s.active_count(), 0);
        assert_eq!(s.total_barriers(), 0);
    }

    #[test]
    fn default_flags() {
        let f = MembarrierFlags::default();
        assert!(f.is_empty());
    }

    #[test]
    fn default_registration() {
        let r = ProcessRegistration::default();
        assert!(!r.active);
    }

    // --- Barrier with non-zero flags (non-rseq) rejected ---

    #[test]
    fn global_with_flags_rejected() {
        let mut s = MembarrierState::new();
        assert_eq!(do_membarrier(&mut s, 1, 1, 1), Err(Error::InvalidArgument));
    }

    #[test]
    fn register_with_flags_rejected() {
        let mut s = MembarrierState::new();
        assert_eq!(do_membarrier(&mut s, 4, 1, 1), Err(Error::InvalidArgument));
    }

    // --- Statistics accumulation ---

    #[test]
    fn barrier_counts_accumulate() {
        let mut s = MembarrierState::new();
        // Issue 3 global barriers.
        for _ in 0..3 {
            do_membarrier(&mut s, 1, 0, 1).unwrap();
        }
        assert_eq!(s.total_barriers(), 3);
        assert_eq!(s.global_count(), 3);
        assert_eq!(s.expedited_count(), 0);
    }
}
