// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU parking for hotplug.
//!
//! When a CPU is taken offline via the hotplug mechanism, it is
//! "parked" — its kernel thread is put into a halt loop where it
//! waits for an unpark IPI. This module manages the park/unpark
//! state machine and coordinates with the scheduler to drain the
//! CPU's run queue before parking.
//!
//! # State Machine
//!
//! ```text
//! Online ──park()──> Draining ──drained()──> Parked
//! Parked ──unpark()──> Waking ──ready()──> Online
//! ```
//!
//! # Architecture
//!
//! ```text
//! CpuParkManager
//!  ├── cpus: [ParkState; MAX_CPUS]
//!  ├── nr_online: u32
//!  └── stats: ParkStats
//! ```

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum CPUs.
const MAX_CPUS: usize = 64;

/// Timeout for draining a CPU's run queue (ticks).
const _DRAIN_TIMEOUT_TICKS: u64 = 10_000;

// ======================================================================
// Types
// ======================================================================

/// CPU park/unpark state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParkPhase {
    /// CPU is online and scheduling.
    Online,
    /// CPU is draining its run queue before parking.
    Draining,
    /// CPU is fully parked (halted).
    Parked,
    /// CPU is waking up from parked state.
    Waking,
    /// CPU was not present at boot.
    NotPresent,
}

impl Default for ParkPhase {
    fn default() -> Self {
        Self::NotPresent
    }
}

/// Per-CPU park state.
#[derive(Debug, Clone, Copy)]
pub struct ParkState {
    /// CPU identifier.
    pub cpu_id: u32,
    /// Current phase.
    pub phase: ParkPhase,
    /// Tick at which the current phase started.
    pub phase_start_tick: u64,
    /// Number of tasks that still need migration.
    pub tasks_remaining: u32,
    /// Total times this CPU has been parked.
    pub park_count: u64,
    /// Total times this CPU has been unparked.
    pub unpark_count: u64,
}

impl ParkState {
    /// Creates a default not-present CPU state.
    pub const fn new() -> Self {
        Self {
            cpu_id: 0,
            phase: ParkPhase::NotPresent,
            phase_start_tick: 0,
            tasks_remaining: 0,
            park_count: 0,
            unpark_count: 0,
        }
    }
}

impl Default for ParkState {
    fn default() -> Self {
        Self::new()
    }
}

/// Park/unpark operation statistics.
#[derive(Debug, Clone, Copy)]
pub struct ParkStats {
    /// Total park operations.
    pub total_parks: u64,
    /// Total unpark operations.
    pub total_unparks: u64,
    /// Total drain timeouts.
    pub drain_timeouts: u64,
    /// Total tasks migrated during park.
    pub tasks_migrated: u64,
    /// Average drain time in ticks.
    pub avg_drain_ticks: u64,
}

impl ParkStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_parks: 0,
            total_unparks: 0,
            drain_timeouts: 0,
            tasks_migrated: 0,
            avg_drain_ticks: 0,
        }
    }
}

impl Default for ParkStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Manages CPU park/unpark operations.
pub struct CpuParkManager {
    /// Per-CPU state.
    cpus: [ParkState; MAX_CPUS],
    /// Number of online CPUs.
    nr_online: u32,
    /// Total CPUs present.
    nr_present: u32,
    /// Statistics.
    stats: ParkStats,
}

impl CpuParkManager {
    /// Creates a new CPU park manager.
    pub const fn new() -> Self {
        Self {
            cpus: [ParkState::new(); MAX_CPUS],
            nr_online: 0,
            nr_present: 0,
            stats: ParkStats::new(),
        }
    }

    /// Initialises with the given number of present CPUs.
    pub fn init(&mut self, nr_present: u32) -> Result<()> {
        if nr_present == 0 || (nr_present as usize) > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.nr_present = nr_present;
        for i in 0..(nr_present as usize) {
            self.cpus[i].cpu_id = i as u32;
            self.cpus[i].phase = ParkPhase::Online;
        }
        self.nr_online = nr_present;
        Ok(())
    }

    /// Begins parking a CPU (takes it offline).
    ///
    /// Transitions from Online to Draining.
    pub fn park(&mut self, cpu_id: u32, current_tick: u64, tasks_to_migrate: u32) -> Result<()> {
        if (cpu_id as usize) >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        // Cannot park the last online CPU.
        if self.nr_online <= 1 {
            return Err(Error::PermissionDenied);
        }
        let cpu = &mut self.cpus[cpu_id as usize];
        if cpu.phase != ParkPhase::Online {
            return Err(Error::InvalidArgument);
        }
        cpu.phase = ParkPhase::Draining;
        cpu.phase_start_tick = current_tick;
        cpu.tasks_remaining = tasks_to_migrate;
        Ok(())
    }

    /// Reports that a task has been migrated off the draining CPU.
    pub fn task_migrated(&mut self, cpu_id: u32) -> Result<()> {
        if (cpu_id as usize) >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let cpu = &mut self.cpus[cpu_id as usize];
        if cpu.phase != ParkPhase::Draining {
            return Err(Error::InvalidArgument);
        }
        cpu.tasks_remaining = cpu.tasks_remaining.saturating_sub(1);
        self.stats.tasks_migrated += 1;
        Ok(())
    }

    /// Completes the drain and parks the CPU.
    ///
    /// Transitions from Draining to Parked.
    pub fn complete_park(&mut self, cpu_id: u32, current_tick: u64) -> Result<()> {
        if (cpu_id as usize) >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let cpu = &mut self.cpus[cpu_id as usize];
        if cpu.phase != ParkPhase::Draining {
            return Err(Error::InvalidArgument);
        }
        if cpu.tasks_remaining > 0 {
            return Err(Error::Busy);
        }
        let drain_ticks = current_tick.wrapping_sub(cpu.phase_start_tick);

        cpu.phase = ParkPhase::Parked;
        cpu.phase_start_tick = current_tick;
        cpu.park_count += 1;
        self.nr_online = self.nr_online.saturating_sub(1);
        self.stats.total_parks += 1;

        // Update average drain time.
        if self.stats.total_parks > 0 {
            self.stats.avg_drain_ticks =
                (self.stats.avg_drain_ticks * (self.stats.total_parks - 1) + drain_ticks)
                    / self.stats.total_parks;
        }
        Ok(())
    }

    /// Begins unparking a CPU (brings it back online).
    ///
    /// Transitions from Parked to Waking.
    pub fn unpark(&mut self, cpu_id: u32, current_tick: u64) -> Result<()> {
        if (cpu_id as usize) >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let cpu = &mut self.cpus[cpu_id as usize];
        if cpu.phase != ParkPhase::Parked {
            return Err(Error::InvalidArgument);
        }
        cpu.phase = ParkPhase::Waking;
        cpu.phase_start_tick = current_tick;
        Ok(())
    }

    /// Completes the unpark (CPU is fully online again).
    ///
    /// Transitions from Waking to Online.
    pub fn complete_unpark(&mut self, cpu_id: u32) -> Result<()> {
        if (cpu_id as usize) >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let cpu = &mut self.cpus[cpu_id as usize];
        if cpu.phase != ParkPhase::Waking {
            return Err(Error::InvalidArgument);
        }
        cpu.phase = ParkPhase::Online;
        cpu.unpark_count += 1;
        self.nr_online += 1;
        self.stats.total_unparks += 1;
        Ok(())
    }

    /// Returns the phase of a CPU.
    pub fn cpu_phase(&self, cpu_id: u32) -> Result<ParkPhase> {
        if (cpu_id as usize) >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.cpus[cpu_id as usize].phase)
    }

    /// Returns the number of online CPUs.
    pub fn nr_online(&self) -> u32 {
        self.nr_online
    }

    /// Returns the number of parked CPUs.
    pub fn nr_parked(&self) -> u32 {
        self.nr_present.saturating_sub(self.nr_online)
    }

    /// Returns statistics.
    pub fn stats(&self) -> &ParkStats {
        &self.stats
    }
}

impl Default for CpuParkManager {
    fn default() -> Self {
        Self::new()
    }
}
