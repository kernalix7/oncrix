// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU hotplug controller — manages CPU online/offline transitions.
//!
//! Coordinates the multi-step process of bringing a CPU online or
//! taking it offline. Each transition moves through a state machine
//! with registered callbacks at each step.
//!
//! # Architecture
//!
//! ```text
//! CpuHotplugCtrl
//!  ├── cpus[MAX_CPUS]
//!  │    ├── state: CpuState
//!  │    ├── target_state: CpuState
//!  │    └── transition_count
//!  ├── callbacks[MAX_CALLBACKS]
//!  └── stats: HotplugCtrlStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/cpu.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum CPUs.
const MAX_CPUS: usize = 64;

/// Maximum hotplug callbacks.
const MAX_CALLBACKS: usize = 64;

// ══════════════════════════════════════════════════════════════
// CpuState
// ══════════════════════════════════════════════════════════════

/// CPU lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum CpuState {
    /// CPU is offline.
    Offline = 0,
    /// CPU is in the bring-up / early boot phase.
    BringUp = 1,
    /// CPU is in AP (application processor) online state.
    ApOnline = 2,
    /// CPU is fully online and scheduling.
    Online = 3,
}

// ══════════════════════════════════════════════════════════════
// CpuHotplugEntry
// ══════════════════════════════════════════════════════════════

/// Per-CPU hotplug state.
#[derive(Debug, Clone, Copy)]
pub struct CpuHotplugEntry {
    /// Current state.
    pub state: CpuState,
    /// Target state for ongoing transition.
    pub target_state: CpuState,
    /// Whether a transition is in progress.
    pub transitioning: bool,
    /// Number of completed transitions.
    pub transition_count: u64,
    /// Whether this CPU was present at boot.
    pub boot_cpu: bool,
}

impl CpuHotplugEntry {
    /// Create an offline CPU entry.
    const fn empty() -> Self {
        Self {
            state: CpuState::Offline,
            target_state: CpuState::Offline,
            transitioning: false,
            transition_count: 0,
            boot_cpu: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// HotplugCallback
// ══════════════════════════════════════════════════════════════

/// A registered hotplug state transition callback.
#[derive(Debug, Clone, Copy)]
pub struct HotplugCallback {
    /// Callback identifier.
    pub id: u32,
    /// State at which this callback fires (on the way up).
    pub state: CpuState,
    /// Callback function ID for startup (bring online).
    pub startup_fn: u64,
    /// Callback function ID for teardown (take offline).
    pub teardown_fn: u64,
    /// Whether this callback is active.
    pub active: bool,
}

impl HotplugCallback {
    /// Create an inactive callback.
    const fn empty() -> Self {
        Self {
            id: 0,
            state: CpuState::Offline,
            startup_fn: 0,
            teardown_fn: 0,
            active: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// HotplugCtrlStats
// ══════════════════════════════════════════════════════════════

/// Hotplug controller statistics.
#[derive(Debug, Clone, Copy)]
pub struct HotplugCtrlStats {
    /// Total CPUs brought online.
    pub total_online: u64,
    /// Total CPUs taken offline.
    pub total_offline: u64,
    /// Total callbacks invoked.
    pub callbacks_invoked: u64,
    /// Total failed transitions.
    pub failed_transitions: u64,
}

impl HotplugCtrlStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            total_online: 0,
            total_offline: 0,
            callbacks_invoked: 0,
            failed_transitions: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// CpuHotplugCtrl
// ══════════════════════════════════════════════════════════════

/// CPU hotplug controller.
pub struct CpuHotplugCtrl {
    /// Per-CPU state.
    cpus: [CpuHotplugEntry; MAX_CPUS],
    /// Registered callbacks.
    callbacks: [HotplugCallback; MAX_CALLBACKS],
    /// Next callback ID.
    next_cb_id: u32,
    /// Number of CPUs present.
    nr_cpus_present: u32,
    /// Statistics.
    stats: HotplugCtrlStats,
}

impl CpuHotplugCtrl {
    /// Create a new CPU hotplug controller.
    pub const fn new() -> Self {
        Self {
            cpus: [const { CpuHotplugEntry::empty() }; MAX_CPUS],
            callbacks: [const { HotplugCallback::empty() }; MAX_CALLBACKS],
            next_cb_id: 1,
            nr_cpus_present: 0,
            stats: HotplugCtrlStats::new(),
        }
    }

    /// Register the boot CPU.
    pub fn register_boot_cpu(&mut self, cpu: u32) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.cpus[c].state = CpuState::Online;
        self.cpus[c].target_state = CpuState::Online;
        self.cpus[c].boot_cpu = true;
        self.nr_cpus_present += 1;
        Ok(())
    }

    /// Register a hotplug state callback.
    pub fn register_callback(
        &mut self,
        state: CpuState,
        startup_fn: u64,
        teardown_fn: u64,
    ) -> Result<u32> {
        let slot = self
            .callbacks
            .iter()
            .position(|c| !c.active)
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_cb_id;
        self.next_cb_id += 1;
        self.callbacks[slot] = HotplugCallback {
            id,
            state,
            startup_fn,
            teardown_fn,
            active: true,
        };
        Ok(id)
    }

    /// Bring a CPU online (transition to Online state).
    pub fn cpu_up(&mut self, cpu: u32) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if matches!(self.cpus[c].state, CpuState::Online) {
            return Err(Error::AlreadyExists);
        }
        self.cpus[c].target_state = CpuState::Online;
        self.cpus[c].transitioning = true;

        // Walk through states.
        let states = [CpuState::BringUp, CpuState::ApOnline, CpuState::Online];
        for target in &states {
            if self.cpus[c].state >= *target {
                continue;
            }
            // Invoke callbacks.
            let cb_count = self.invoke_startup_callbacks(c, *target);
            self.stats.callbacks_invoked += cb_count as u64;
            self.cpus[c].state = *target;
        }

        self.cpus[c].transitioning = false;
        self.cpus[c].transition_count += 1;
        self.stats.total_online += 1;
        self.nr_cpus_present += 1;
        Ok(())
    }

    /// Take a CPU offline.
    pub fn cpu_down(&mut self, cpu: u32) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if matches!(self.cpus[c].state, CpuState::Offline) {
            return Err(Error::InvalidArgument);
        }
        if self.cpus[c].boot_cpu {
            return Err(Error::PermissionDenied);
        }
        self.cpus[c].target_state = CpuState::Offline;
        self.cpus[c].transitioning = true;
        self.cpus[c].state = CpuState::Offline;
        self.cpus[c].transitioning = false;
        self.cpus[c].transition_count += 1;
        self.stats.total_offline += 1;
        self.nr_cpus_present = self.nr_cpus_present.saturating_sub(1);
        Ok(())
    }

    /// Return CPU state.
    pub fn cpu_state(&self, cpu: u32) -> Result<CpuState> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.cpus[c].state)
    }

    /// Return number of online CPUs.
    pub fn online_count(&self) -> u32 {
        self.cpus
            .iter()
            .filter(|c| matches!(c.state, CpuState::Online))
            .count() as u32
    }

    /// Return statistics.
    pub fn stats(&self) -> HotplugCtrlStats {
        self.stats
    }

    // ── Internal ─────────────────────────────────────────────

    fn invoke_startup_callbacks(&self, _cpu: usize, _state: CpuState) -> u32 {
        self.callbacks
            .iter()
            .filter(|c| c.active && c.state == _state)
            .count() as u32
    }
}
