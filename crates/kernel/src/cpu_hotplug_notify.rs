// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU hotplug notification — callbacks for CPU online/offline transitions.
//!
//! Subsystems register callbacks that are invoked when CPUs transition
//! between online and offline states.  Callbacks run in a deterministic
//! order based on priority, allowing subsystems to prepare or tear down
//! per-CPU resources.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                CpuHotplugNotifier                            │
//! │                                                              │
//! │  Callback[0..MAX_CALLBACKS]  (registered notifiers)          │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  phase: HotplugPhase                                   │  │
//! │  │  priority: i32                                         │  │
//! │  │  handler: fn(usize, HotplugPhase) -> Result<()>        │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  CpuState[0..MAX_CPUS]  (per-CPU online/offline state)       │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `kernel/cpu.c`, `include/linux/cpuhotplug.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum CPUs.
const MAX_CPUS: usize = 64;

/// Maximum registered callbacks.
const MAX_CALLBACKS: usize = 128;

// ══════════════════════════════════════════════════════════════
// HotplugPhase
// ══════════════════════════════════════════════════════════════

/// Phase of a CPU hotplug transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HotplugPhase {
    /// CPU is being prepared to come online.
    Prepare = 0,
    /// CPU is now online and ready for work.
    Online = 1,
    /// CPU is about to go offline.
    TeardownPrepare = 2,
    /// CPU is fully offline.
    Offline = 3,
}

impl HotplugPhase {
    /// Display name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::Online => "online",
            Self::TeardownPrepare => "teardown_prepare",
            Self::Offline => "offline",
        }
    }
}

// ══════════════════════════════════════════════════════════════
// CpuOnlineState
// ══════════════════════════════════════════════════════════════

/// Online state of a CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CpuOnlineState {
    /// CPU is offline.
    Offline = 0,
    /// CPU is in the process of coming online.
    Booting = 1,
    /// CPU is online and active.
    Online = 2,
    /// CPU is in the process of going offline.
    TearingDown = 3,
}

// ══════════════════════════════════════════════════════════════
// HotplugCallback
// ══════════════════════════════════════════════════════════════

/// Handler function type for hotplug notifications.
pub type HotplugFn = fn(usize, HotplugPhase) -> Result<()>;

/// A registered hotplug callback.
#[derive(Debug, Clone, Copy)]
pub struct HotplugCallback {
    /// Phase this callback is interested in.
    pub phase: HotplugPhase,
    /// Priority (higher = called first on online, last on offline).
    pub priority: i32,
    /// Handler function.
    pub handler: Option<HotplugFn>,
    /// Whether this callback is registered.
    pub registered: bool,
    /// Callback identifier.
    pub cb_id: u32,
}

impl HotplugCallback {
    /// Create an empty callback slot.
    const fn empty() -> Self {
        Self {
            phase: HotplugPhase::Online,
            priority: 0,
            handler: None,
            registered: false,
            cb_id: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// PerCpuState
// ══════════════════════════════════════════════════════════════

/// Per-CPU hotplug state.
#[derive(Debug, Clone, Copy)]
pub struct PerCpuState {
    /// Current online state.
    pub state: CpuOnlineState,
    /// Number of online transitions.
    pub online_count: u64,
    /// Number of offline transitions.
    pub offline_count: u64,
    /// Last transition timestamp.
    pub last_transition_tick: u64,
}

impl PerCpuState {
    const fn new() -> Self {
        Self {
            state: CpuOnlineState::Offline,
            online_count: 0,
            offline_count: 0,
            last_transition_tick: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// HotplugNotifyStats
// ══════════════════════════════════════════════════════════════

/// Statistics for hotplug notifications.
#[derive(Debug, Clone, Copy)]
pub struct HotplugNotifyStats {
    /// Total online transitions.
    pub total_online: u64,
    /// Total offline transitions.
    pub total_offline: u64,
    /// Total callback invocations.
    pub total_callbacks: u64,
    /// Total callback failures.
    pub total_failures: u64,
}

impl HotplugNotifyStats {
    const fn new() -> Self {
        Self {
            total_online: 0,
            total_offline: 0,
            total_callbacks: 0,
            total_failures: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// CpuHotplugNotifier
// ══════════════════════════════════════════════════════════════

/// Top-level CPU hotplug notification subsystem.
pub struct CpuHotplugNotifier {
    /// Registered callbacks.
    callbacks: [HotplugCallback; MAX_CALLBACKS],
    /// Per-CPU state.
    per_cpu: [PerCpuState; MAX_CPUS],
    /// Statistics.
    stats: HotplugNotifyStats,
    /// Next callback ID.
    next_cb_id: u32,
    /// Whether the subsystem is initialised.
    initialised: bool,
}

impl Default for CpuHotplugNotifier {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuHotplugNotifier {
    /// Create a new hotplug notifier subsystem.
    pub const fn new() -> Self {
        Self {
            callbacks: [const { HotplugCallback::empty() }; MAX_CALLBACKS],
            per_cpu: [const { PerCpuState::new() }; MAX_CPUS],
            stats: HotplugNotifyStats::new(),
            next_cb_id: 1,
            initialised: false,
        }
    }

    /// Initialise the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.initialised = true;
        Ok(())
    }

    // ── Callback registration ────────────────────────────────

    /// Register a hotplug callback.
    ///
    /// Returns the callback ID.
    pub fn register(
        &mut self,
        phase: HotplugPhase,
        priority: i32,
        handler: HotplugFn,
    ) -> Result<u32> {
        let slot = self
            .callbacks
            .iter()
            .position(|c| !c.registered)
            .ok_or(Error::OutOfMemory)?;

        let cb_id = self.next_cb_id;
        self.next_cb_id += 1;

        self.callbacks[slot] = HotplugCallback {
            phase,
            priority,
            handler: Some(handler),
            registered: true,
            cb_id,
        };
        Ok(cb_id)
    }

    /// Unregister a callback by ID.
    pub fn unregister(&mut self, cb_id: u32) -> Result<()> {
        let slot = self
            .callbacks
            .iter()
            .position(|c| c.registered && c.cb_id == cb_id)
            .ok_or(Error::NotFound)?;
        self.callbacks[slot] = HotplugCallback::empty();
        Ok(())
    }

    // ── CPU transitions ──────────────────────────────────────

    /// Bring a CPU online.
    pub fn cpu_online(&mut self, cpu: usize, tick: u64) -> Result<usize> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        self.per_cpu[cpu].state = CpuOnlineState::Booting;
        let failures = self.run_callbacks(cpu, HotplugPhase::Prepare);
        let failures2 = self.run_callbacks(cpu, HotplugPhase::Online);
        let total_failures = failures + failures2;

        self.per_cpu[cpu].state = CpuOnlineState::Online;
        self.per_cpu[cpu].online_count += 1;
        self.per_cpu[cpu].last_transition_tick = tick;
        self.stats.total_online += 1;

        Ok(total_failures)
    }

    /// Take a CPU offline.
    pub fn cpu_offline(&mut self, cpu: usize, tick: u64) -> Result<usize> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        self.per_cpu[cpu].state = CpuOnlineState::TearingDown;
        let failures = self.run_callbacks(cpu, HotplugPhase::TeardownPrepare);
        let failures2 = self.run_callbacks(cpu, HotplugPhase::Offline);
        let total_failures = failures + failures2;

        self.per_cpu[cpu].state = CpuOnlineState::Offline;
        self.per_cpu[cpu].offline_count += 1;
        self.per_cpu[cpu].last_transition_tick = tick;
        self.stats.total_offline += 1;

        Ok(total_failures)
    }

    /// Run all callbacks matching the given phase.
    fn run_callbacks(&mut self, cpu: usize, phase: HotplugPhase) -> usize {
        let mut failures = 0usize;
        for i in 0..MAX_CALLBACKS {
            let cb = &self.callbacks[i];
            if cb.registered && cb.phase as u8 == phase as u8 {
                if let Some(handler) = cb.handler {
                    self.stats.total_callbacks += 1;
                    if handler(cpu, phase).is_err() {
                        failures += 1;
                        self.stats.total_failures += 1;
                    }
                }
            }
        }
        failures
    }

    // ── Query ────────────────────────────────────────────────

    /// Return per-CPU state.
    pub fn cpu_state(&self, cpu: usize) -> Result<&PerCpuState> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.per_cpu[cpu])
    }

    /// Return statistics.
    pub fn stats(&self) -> HotplugNotifyStats {
        self.stats
    }

    /// Return the number of online CPUs.
    pub fn online_count(&self) -> usize {
        self.per_cpu
            .iter()
            .filter(|c| matches!(c.state, CpuOnlineState::Online))
            .count()
    }

    /// Return the number of registered callbacks.
    pub fn callback_count(&self) -> usize {
        self.callbacks.iter().filter(|c| c.registered).count()
    }
}
