// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Tick broadcast for idle CPUs.
//!
//! When a CPU enters a deep idle state (C-state), its local APIC
//! timer may stop. The tick broadcast framework designates one CPU
//! as the broadcaster that fires a hardware timer on behalf of
//! sleeping CPUs, waking them when their next event is due.
//!
//! # Modes
//!
//! - **Periodic** — broadcaster fires at the system tick rate and
//!   sends IPIs to all registered CPUs.
//! - **One-shot** — broadcaster programs the next event to the
//!   earliest deadline among all registered CPUs.
//!
//! # Architecture
//!
//! ```text
//! TickBroadcast
//!  ├── mode: BroadcastMode
//!  ├── broadcaster_cpu: u32
//!  ├── cpu_state: [BroadcastCpuState; MAX_CPUS]
//!  └── stats: BroadcastStats
//! ```

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum CPUs.
const MAX_CPUS: usize = 64;

/// Sentinel for "no deadline".
const NO_DEADLINE: u64 = u64::MAX;

// ======================================================================
// Types
// ======================================================================

/// Broadcast timer mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastMode {
    /// Fire at every system tick.
    Periodic,
    /// Fire at the next earliest deadline.
    OneShot,
    /// Broadcast is disabled.
    Disabled,
}

impl Default for BroadcastMode {
    fn default() -> Self {
        Self::Disabled
    }
}

/// Per-CPU broadcast state.
#[derive(Debug, Clone, Copy)]
pub struct BroadcastCpuState {
    /// CPU identifier.
    pub cpu_id: u32,
    /// Whether this CPU is registered for broadcast.
    pub registered: bool,
    /// Whether this CPU is currently in deep idle.
    pub deep_idle: bool,
    /// Next event deadline (absolute ticks).
    pub next_event: u64,
    /// Number of broadcast wakeups received.
    pub wakeups: u64,
}

impl BroadcastCpuState {
    /// Creates a default CPU state.
    pub const fn new() -> Self {
        Self {
            cpu_id: 0,
            registered: false,
            deep_idle: false,
            next_event: NO_DEADLINE,
            wakeups: 0,
        }
    }
}

impl Default for BroadcastCpuState {
    fn default() -> Self {
        Self::new()
    }
}

/// Broadcast subsystem statistics.
#[derive(Debug, Clone, Copy)]
pub struct BroadcastStats {
    /// Total broadcast events fired.
    pub events_fired: u64,
    /// Total IPIs sent.
    pub ipis_sent: u64,
    /// Times a CPU was woken early (spurious).
    pub spurious_wakeups: u64,
    /// Times the broadcaster was changed.
    pub broadcaster_changes: u64,
}

impl BroadcastStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            events_fired: 0,
            ipis_sent: 0,
            spurious_wakeups: 0,
            broadcaster_changes: 0,
        }
    }
}

impl Default for BroadcastStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Tick broadcast subsystem.
pub struct TickBroadcast {
    /// Current broadcast mode.
    mode: BroadcastMode,
    /// CPU acting as broadcaster.
    broadcaster_cpu: u32,
    /// Per-CPU state.
    cpu_state: [BroadcastCpuState; MAX_CPUS],
    /// Number of online CPUs.
    nr_cpus: u32,
    /// Number of CPUs registered for broadcast.
    nr_registered: u32,
    /// Statistics.
    stats: BroadcastStats,
}

impl TickBroadcast {
    /// Creates a new tick broadcast subsystem.
    pub const fn new() -> Self {
        Self {
            mode: BroadcastMode::Disabled,
            broadcaster_cpu: 0,
            cpu_state: [BroadcastCpuState::new(); MAX_CPUS],
            nr_cpus: 1,
            nr_registered: 0,
            stats: BroadcastStats::new(),
        }
    }

    /// Initialises the broadcast subsystem with a broadcaster CPU.
    pub fn init(&mut self, nr_cpus: u32, broadcaster: u32, mode: BroadcastMode) -> Result<()> {
        if nr_cpus == 0 || (nr_cpus as usize) > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if (broadcaster as usize) >= (nr_cpus as usize) {
            return Err(Error::InvalidArgument);
        }
        self.nr_cpus = nr_cpus;
        self.broadcaster_cpu = broadcaster;
        self.mode = mode;
        for i in 0..(nr_cpus as usize) {
            self.cpu_state[i].cpu_id = i as u32;
        }
        Ok(())
    }

    /// Registers a CPU for tick broadcast (entering deep idle).
    pub fn register_cpu(&mut self, cpu_id: u32, next_event: u64) -> Result<()> {
        if (cpu_id as usize) >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let state = &mut self.cpu_state[cpu_id as usize];
        if state.registered {
            // Update deadline only.
            state.next_event = next_event;
            return Ok(());
        }
        state.registered = true;
        state.deep_idle = true;
        state.next_event = next_event;
        self.nr_registered += 1;
        Ok(())
    }

    /// Unregisters a CPU (exiting deep idle).
    pub fn unregister_cpu(&mut self, cpu_id: u32) -> Result<()> {
        if (cpu_id as usize) >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let state = &mut self.cpu_state[cpu_id as usize];
        if !state.registered {
            return Ok(());
        }
        state.registered = false;
        state.deep_idle = false;
        state.next_event = NO_DEADLINE;
        self.nr_registered = self.nr_registered.saturating_sub(1);
        Ok(())
    }

    /// Finds the earliest deadline among registered CPUs.
    pub fn earliest_deadline(&self) -> u64 {
        let mut earliest = NO_DEADLINE;
        for i in 0..(self.nr_cpus as usize) {
            let state = &self.cpu_state[i];
            if state.registered && state.next_event < earliest {
                earliest = state.next_event;
            }
        }
        earliest
    }

    /// Processes a broadcast event at the given tick.
    ///
    /// Returns the number of CPUs that need to be woken via IPI.
    pub fn fire_event(&mut self, current_tick: u64) -> u32 {
        if self.mode == BroadcastMode::Disabled {
            return 0;
        }
        self.stats.events_fired += 1;
        let mut woken = 0u32;

        for i in 0..(self.nr_cpus as usize) {
            let state = &mut self.cpu_state[i];
            if !state.registered || !state.deep_idle {
                continue;
            }
            let should_wake = match self.mode {
                BroadcastMode::Periodic => true,
                BroadcastMode::OneShot => current_tick >= state.next_event,
                BroadcastMode::Disabled => false,
            };
            if should_wake {
                state.wakeups += 1;
                state.deep_idle = false;
                woken += 1;
            }
        }
        self.stats.ipis_sent += woken as u64;
        woken
    }

    /// Changes the broadcaster CPU.
    pub fn set_broadcaster(&mut self, cpu_id: u32) -> Result<()> {
        if (cpu_id as usize) >= (self.nr_cpus as usize) {
            return Err(Error::InvalidArgument);
        }
        self.broadcaster_cpu = cpu_id;
        self.stats.broadcaster_changes += 1;
        Ok(())
    }

    /// Returns the current broadcast mode.
    pub fn mode(&self) -> BroadcastMode {
        self.mode
    }

    /// Returns the broadcaster CPU.
    pub fn broadcaster_cpu(&self) -> u32 {
        self.broadcaster_cpu
    }

    /// Returns the number of registered CPUs.
    pub fn nr_registered(&self) -> u32 {
        self.nr_registered
    }

    /// Returns broadcast statistics.
    pub fn stats(&self) -> &BroadcastStats {
        &self.stats
    }
}

impl Default for TickBroadcast {
    fn default() -> Self {
        Self::new()
    }
}
