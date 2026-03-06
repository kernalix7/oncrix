// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory barrier expedited — process-wide memory ordering.
//!
//! Implements the `membarrier()` system call, which provides
//! process-wide memory barriers suitable for RCU-like
//! synchronization patterns. The key use case is replacing
//! per-access memory fences in a read-mostly data structure with
//! a single expedited barrier on the write side.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                     MembarrierTable                           │
//! │                                                              │
//! │  MembarrierState[0..MAX_MEMBARRIER_PIDS]  (per-PID state)    │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  pid, registered_global, registered_private,           │  │
//! │  │  registered_sync_core, generation [u64; MAX_CPUS]      │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  MembarrierStats (global counters)                           │
//! │  - total_calls, global_barriers, private_barriers,           │
//! │    ipis_sent                                                 │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Commands
//!
//! - **Query**: Returns a bitmask of supported commands.
//! - **Global/GlobalExpedited**: Barrier visible to all threads
//!   in all processes. Expedited variant uses IPI.
//! - **RegisterGlobalExpedited**: Opt-in to receive expedited
//!   global barriers.
//! - **Private/PrivateExpedited**: Barrier visible only to
//!   threads in the calling process.
//! - **RegisterPrivateExpedited**: Opt-in to receive expedited
//!   private barriers.
//! - **PrivateExpeditedSyncCore**: Serialize instruction streams
//!   across CPUs after code patching.
//! - **RegisterPrivateExpeditedSyncCore**: Opt-in for sync-core
//!   barriers.
//!
//! # Reference
//!
//! Linux `kernel/sched/membarrier.c`,
//! `include/uapi/linux/membarrier.h`, `man membarrier(2)`.

use oncrix_lib::{Error, Result};
use oncrix_process::pid::Pid;

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum number of CPUs for generation counters.
const MAX_CPUS: usize = 8;

/// Maximum number of per-PID membarrier states.
const MAX_MEMBARRIER_PIDS: usize = 256;

/// Bitmask bit for `Query`.
const CMD_QUERY: u32 = 0;

/// Bitmask bit for `Global`.
const CMD_GLOBAL: u32 = 1 << 0;

/// Bitmask bit for `GlobalExpedited`.
const CMD_GLOBAL_EXPEDITED: u32 = 1 << 1;

/// Bitmask bit for `RegisterGlobalExpedited`.
const CMD_REGISTER_GLOBAL_EXPEDITED: u32 = 1 << 2;

/// Bitmask bit for `Private`.
const CMD_PRIVATE: u32 = 1 << 3;

/// Bitmask bit for `PrivateExpedited`.
const CMD_PRIVATE_EXPEDITED: u32 = 1 << 4;

/// Bitmask bit for `RegisterPrivateExpedited`.
const CMD_REGISTER_PRIVATE_EXPEDITED: u32 = 1 << 5;

/// Bitmask bit for `PrivateExpeditedSyncCore`.
const CMD_PRIVATE_EXPEDITED_SYNC_CORE: u32 = 1 << 6;

/// Bitmask bit for `RegisterPrivateExpeditedSyncCore`.
const CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE: u32 = 1 << 7;

/// Full supported commands bitmask.
const SUPPORTED_COMMANDS: u32 = CMD_GLOBAL
    | CMD_GLOBAL_EXPEDITED
    | CMD_REGISTER_GLOBAL_EXPEDITED
    | CMD_PRIVATE
    | CMD_PRIVATE_EXPEDITED
    | CMD_REGISTER_PRIVATE_EXPEDITED
    | CMD_PRIVATE_EXPEDITED_SYNC_CORE
    | CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE;

// ══════════════════════════════════════════════════════════════
// MembarrierCmd
// ══════════════════════════════════════════════════════════════

/// Membarrier command identifiers.
///
/// Each variant corresponds to a specific barrier operation
/// or registration request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MembarrierCmd {
    /// Query supported commands (returns bitmask).
    Query = 0,
    /// Issue a global memory barrier.
    Global = 1,
    /// Issue a global expedited memory barrier (IPI).
    GlobalExpedited = 2,
    /// Register for global expedited barriers.
    RegisterGlobalExpedited = 3,
    /// Issue a private memory barrier (current process).
    Private = 4,
    /// Issue a private expedited memory barrier.
    PrivateExpedited = 5,
    /// Register for private expedited barriers.
    RegisterPrivateExpedited = 6,
    /// Issue a private expedited sync-core barrier.
    PrivateExpeditedSyncCore = 7,
    /// Register for private expedited sync-core barriers.
    RegisterPrivateExpeditedSyncCore = 8,
}

impl MembarrierCmd {
    /// Convert from raw u8.
    pub fn from_u8(val: u8) -> Result<Self> {
        match val {
            0 => Ok(Self::Query),
            1 => Ok(Self::Global),
            2 => Ok(Self::GlobalExpedited),
            3 => Ok(Self::RegisterGlobalExpedited),
            4 => Ok(Self::Private),
            5 => Ok(Self::PrivateExpedited),
            6 => Ok(Self::RegisterPrivateExpedited),
            7 => Ok(Self::PrivateExpeditedSyncCore),
            8 => Ok(Self::RegisterPrivateExpeditedSyncCore),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Return the command bitmask value.
    pub fn bitmask(self) -> u32 {
        match self {
            Self::Query => CMD_QUERY,
            Self::Global => CMD_GLOBAL,
            Self::GlobalExpedited => CMD_GLOBAL_EXPEDITED,
            Self::RegisterGlobalExpedited => CMD_REGISTER_GLOBAL_EXPEDITED,
            Self::Private => CMD_PRIVATE,
            Self::PrivateExpedited => CMD_PRIVATE_EXPEDITED,
            Self::RegisterPrivateExpedited => CMD_REGISTER_PRIVATE_EXPEDITED,
            Self::PrivateExpeditedSyncCore => CMD_PRIVATE_EXPEDITED_SYNC_CORE,
            Self::RegisterPrivateExpeditedSyncCore => CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE,
        }
    }

    /// Check whether this is a registration command.
    pub fn is_register(self) -> bool {
        matches!(
            self,
            Self::RegisterGlobalExpedited
                | Self::RegisterPrivateExpedited
                | Self::RegisterPrivateExpeditedSyncCore
        )
    }

    /// Check whether this is an expedited command.
    pub fn is_expedited(self) -> bool {
        matches!(
            self,
            Self::GlobalExpedited | Self::PrivateExpedited | Self::PrivateExpeditedSyncCore
        )
    }
}

// ══════════════════════════════════════════════════════════════
// MembarrierFlags
// ══════════════════════════════════════════════════════════════

/// Additional flags for membarrier operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MembarrierFlags(u32);

impl MembarrierFlags {
    /// No flags.
    pub const NONE: Self = Self(0);

    /// RSEQ flag — coordinate with restartable sequences.
    pub const RSEQ: Self = Self(1 << 0);

    /// Create flags from a raw u32.
    pub const fn from_raw(val: u32) -> Self {
        Self(val)
    }

    /// Return the raw flags value.
    pub const fn as_raw(self) -> u32 {
        self.0
    }

    /// Check whether the RSEQ flag is set.
    pub const fn has_rseq(self) -> bool {
        (self.0 & 1) != 0
    }

    /// Validate flags (only known bits set).
    pub fn validate(self) -> Result<()> {
        if self.0 & !1 != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ══════════════════════════════════════════════════════════════
// MembarrierState
// ══════════════════════════════════════════════════════════════

/// Per-PID membarrier registration state.
///
/// Tracks which barrier types a process has opted into and
/// maintains per-CPU generation counters for tracking barrier
/// completion.
pub struct MembarrierState {
    /// The PID this state belongs to.
    pid: Pid,
    /// Whether this slot is allocated.
    allocated: bool,
    /// Registered for global expedited barriers.
    pub registered_global: bool,
    /// Registered for private expedited barriers.
    pub registered_private: bool,
    /// Registered for private expedited sync-core barriers.
    pub registered_sync_core: bool,
    /// Per-CPU generation counters.
    ///
    /// Incremented when an expedited barrier is issued. CPUs
    /// compare their local counter to detect pending barriers.
    pub generation_counters: [u64; MAX_CPUS],
    /// Number of barrier commands executed for this PID.
    pub barrier_count: u64,
    /// Number of IPIs sent for this PID.
    pub ipi_count: u64,
}

impl MembarrierState {
    /// Create an unallocated state.
    pub const fn new() -> Self {
        Self {
            pid: Pid::new(0),
            allocated: false,
            registered_global: false,
            registered_private: false,
            registered_sync_core: false,
            generation_counters: [0u64; MAX_CPUS],
            barrier_count: 0,
            ipi_count: 0,
        }
    }

    /// Allocate this state for a PID.
    pub fn allocate(&mut self, pid: Pid) {
        self.pid = pid;
        self.allocated = true;
        self.registered_global = false;
        self.registered_private = false;
        self.registered_sync_core = false;
        self.generation_counters = [0u64; MAX_CPUS];
        self.barrier_count = 0;
        self.ipi_count = 0;
    }

    /// Release this state.
    pub fn release(&mut self) {
        self.allocated = false;
        self.registered_global = false;
        self.registered_private = false;
        self.registered_sync_core = false;
    }

    /// Return the PID.
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// Check whether this state is allocated.
    pub fn is_allocated(&self) -> bool {
        self.allocated
    }

    /// Increment all generation counters (global barrier).
    pub fn increment_all_generations(&mut self) {
        for counter in &mut self.generation_counters {
            *counter = counter.wrapping_add(1);
        }
        self.barrier_count += 1;
        self.ipi_count += MAX_CPUS as u64;
    }

    /// Increment generation counter for a specific CPU.
    pub fn increment_cpu_generation(&mut self, cpu: usize) -> Result<()> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.generation_counters[cpu] = self.generation_counters[cpu].wrapping_add(1);
        self.ipi_count += 1;
        Ok(())
    }

    /// Return the generation counter for a CPU.
    pub fn cpu_generation(&self, cpu: usize) -> Result<u64> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.generation_counters[cpu])
    }
}

// ══════════════════════════════════════════════════════════════
// MembarrierStats
// ══════════════════════════════════════════════════════════════

/// Global membarrier subsystem statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MembarrierStats {
    /// Total membarrier calls.
    pub total_calls: u64,
    /// Total global barrier operations.
    pub global_barriers: u64,
    /// Total private barrier operations.
    pub private_barriers: u64,
    /// Total IPIs sent (or simulated).
    pub ipis_sent: u64,
    /// Total query operations.
    pub queries: u64,
    /// Total registrations.
    pub registrations: u64,
    /// Total errors.
    pub errors: u64,
}

impl MembarrierStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_calls: 0,
            global_barriers: 0,
            private_barriers: 0,
            ipis_sent: 0,
            queries: 0,
            registrations: 0,
            errors: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// MembarrierTable
// ══════════════════════════════════════════════════════════════

/// System-wide membarrier state table.
///
/// Manages per-PID registration and dispatches barrier commands.
pub struct MembarrierTable {
    /// Per-PID states.
    states: [MembarrierState; MAX_MEMBARRIER_PIDS],
    /// Global statistics.
    stats: MembarrierStats,
    /// Number of active CPUs in the system.
    nr_cpus: usize,
}

impl MembarrierTable {
    /// Create a new empty membarrier table.
    pub const fn new() -> Self {
        Self {
            states: [const { MembarrierState::new() }; MAX_MEMBARRIER_PIDS],
            stats: MembarrierStats::new(),
            nr_cpus: MAX_CPUS,
        }
    }

    /// Set the number of active CPUs.
    pub fn set_nr_cpus(&mut self, nr_cpus: usize) -> Result<()> {
        if nr_cpus == 0 || nr_cpus > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.nr_cpus = nr_cpus;
        Ok(())
    }

    /// Allocate membarrier state for a PID.
    pub fn alloc_state(&mut self, pid: Pid) -> Result<usize> {
        // Check for duplicate
        if self
            .states
            .iter()
            .any(|s| s.is_allocated() && s.pid().as_u64() == pid.as_u64())
        {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .states
            .iter()
            .position(|s| !s.is_allocated())
            .ok_or(Error::OutOfMemory)?;

        self.states[slot].allocate(pid);
        Ok(slot)
    }

    /// Free membarrier state for a PID.
    pub fn free_state(&mut self, pid: Pid) -> Result<()> {
        let slot = self.find_state_idx(pid)?;
        self.states[slot].release();
        Ok(())
    }

    /// Execute a membarrier command.
    ///
    /// This is the main entry point, corresponding to the
    /// `membarrier()` system call.
    pub fn do_membarrier(
        &mut self,
        pid: Pid,
        cmd: MembarrierCmd,
        flags: MembarrierFlags,
    ) -> Result<u32> {
        self.stats.total_calls += 1;
        flags.validate()?;

        match cmd {
            MembarrierCmd::Query => {
                self.stats.queries += 1;
                Ok(SUPPORTED_COMMANDS)
            }

            MembarrierCmd::Global => {
                self.execute_global_barrier()?;
                Ok(0)
            }

            MembarrierCmd::GlobalExpedited => {
                self.execute_global_expedited(pid)?;
                Ok(0)
            }

            MembarrierCmd::RegisterGlobalExpedited => {
                self.register_global_expedited(pid)?;
                Ok(0)
            }

            MembarrierCmd::Private => {
                self.execute_private_barrier(pid)?;
                Ok(0)
            }

            MembarrierCmd::PrivateExpedited => {
                self.execute_private_expedited(pid)?;
                Ok(0)
            }

            MembarrierCmd::RegisterPrivateExpedited => {
                self.register_private_expedited(pid)?;
                Ok(0)
            }

            MembarrierCmd::PrivateExpeditedSyncCore => {
                self.execute_sync_core(pid)?;
                Ok(0)
            }

            MembarrierCmd::RegisterPrivateExpeditedSyncCore => {
                self.register_sync_core(pid)?;
                Ok(0)
            }
        }
    }

    /// Execute a global (non-expedited) memory barrier.
    ///
    /// This conceptually synchronizes all running threads.
    /// In a real implementation, this would issue a full
    /// memory barrier on all CPUs via IPI.
    fn execute_global_barrier(&mut self) -> Result<()> {
        self.stats.global_barriers += 1;
        // Increment generation counters for all allocated states
        for state in &mut self.states {
            if state.is_allocated() {
                state.increment_all_generations();
            }
        }
        self.stats.ipis_sent += self.nr_cpus as u64;
        Ok(())
    }

    /// Execute a global expedited barrier.
    ///
    /// Only affects processes that have registered for global
    /// expedited barriers.
    fn execute_global_expedited(&mut self, _pid: Pid) -> Result<()> {
        self.stats.global_barriers += 1;
        for state in &mut self.states {
            if state.is_allocated() && state.registered_global {
                state.increment_all_generations();
            }
        }
        self.stats.ipis_sent += self.nr_cpus as u64;
        Ok(())
    }

    /// Register a process for global expedited barriers.
    fn register_global_expedited(&mut self, pid: Pid) -> Result<()> {
        let slot = self.find_state_idx(pid)?;
        self.states[slot].registered_global = true;
        self.stats.registrations += 1;
        Ok(())
    }

    /// Execute a private (process-scoped) barrier.
    fn execute_private_barrier(&mut self, pid: Pid) -> Result<()> {
        let slot = self.find_state_idx(pid)?;
        self.states[slot].increment_all_generations();
        self.stats.private_barriers += 1;
        self.stats.ipis_sent += self.nr_cpus as u64;
        Ok(())
    }

    /// Execute a private expedited barrier.
    fn execute_private_expedited(&mut self, pid: Pid) -> Result<()> {
        let slot = self.find_state_idx(pid)?;
        if !self.states[slot].registered_private {
            return Err(Error::PermissionDenied);
        }
        self.states[slot].increment_all_generations();
        self.stats.private_barriers += 1;
        self.stats.ipis_sent += self.nr_cpus as u64;
        Ok(())
    }

    /// Register a process for private expedited barriers.
    fn register_private_expedited(&mut self, pid: Pid) -> Result<()> {
        let slot = self.find_state_idx(pid)?;
        self.states[slot].registered_private = true;
        self.stats.registrations += 1;
        Ok(())
    }

    /// Execute a private expedited sync-core barrier.
    fn execute_sync_core(&mut self, pid: Pid) -> Result<()> {
        let slot = self.find_state_idx(pid)?;
        if !self.states[slot].registered_sync_core {
            return Err(Error::PermissionDenied);
        }
        self.states[slot].increment_all_generations();
        self.stats.private_barriers += 1;
        self.stats.ipis_sent += self.nr_cpus as u64;
        Ok(())
    }

    /// Register a process for private expedited sync-core.
    fn register_sync_core(&mut self, pid: Pid) -> Result<()> {
        let slot = self.find_state_idx(pid)?;
        self.states[slot].registered_sync_core = true;
        self.stats.registrations += 1;
        Ok(())
    }

    /// Find the state index for a PID.
    fn find_state_idx(&self, pid: Pid) -> Result<usize> {
        self.states
            .iter()
            .position(|s| s.is_allocated() && s.pid().as_u64() == pid.as_u64())
            .ok_or(Error::NotFound)
    }

    /// Return a reference to a PID's state.
    pub fn find_state(&self, pid: Pid) -> Result<&MembarrierState> {
        let slot = self.find_state_idx(pid)?;
        Ok(&self.states[slot])
    }

    /// Return global statistics.
    pub fn stats(&self) -> &MembarrierStats {
        &self.stats
    }

    /// Return the number of allocated states.
    pub fn allocated_count(&self) -> usize {
        self.states.iter().filter(|s| s.is_allocated()).count()
    }
}

/// Execute a membarrier command for a PID.
///
/// Convenience wrapper around `MembarrierTable::do_membarrier`.
pub fn do_membarrier(
    table: &mut MembarrierTable,
    pid: Pid,
    cmd: MembarrierCmd,
    flags: MembarrierFlags,
) -> Result<u32> {
    table.do_membarrier(pid, cmd, flags)
}
