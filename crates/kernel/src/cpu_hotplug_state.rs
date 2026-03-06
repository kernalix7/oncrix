// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU hotplug state machine.
//!
//! Implements the state machine that manages CPU lifecycle transitions
//! during hotplug operations. Each CPU progresses through a series of
//! states when being brought online or taken offline, with registered
//! callbacks invoked at each transition.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of CPUs supported.
const MAX_CPUS: usize = 64;

/// Maximum callbacks per state transition.
const MAX_CALLBACKS_PER_STATE: usize = 16;

/// Maximum total state transitions tracked.
const MAX_TRANSITION_LOG: usize = 256;

// ── Types ────────────────────────────────────────────────────────────

/// CPU hotplug states in lifecycle order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HotplugState {
    /// CPU is offline and not available.
    Offline,
    /// CPU is being prepared for bring-up.
    BringupPrepare,
    /// CPU is starting AP bootstrap.
    ApOnline,
    /// CPU is online and idle.
    OnlineIdle,
    /// CPU is fully online and scheduling.
    OnlineActive,
    /// CPU is being prepared for teardown.
    TeardownPrepare,
    /// CPU is in the process of dying.
    Dying,
    /// CPU has been removed from the system.
    Removed,
}

impl Default for HotplugState {
    fn default() -> Self {
        Self::Offline
    }
}

/// Per-CPU hotplug state tracking.
#[derive(Debug, Clone)]
pub struct CpuHotplugInfo {
    /// CPU identifier.
    cpu_id: u32,
    /// Current state.
    state: HotplugState,
    /// Target state for ongoing transition.
    target_state: HotplugState,
    /// Whether a transition is in progress.
    transitioning: bool,
    /// Number of successful online operations.
    online_count: u64,
    /// Number of successful offline operations.
    offline_count: u64,
    /// Number of failed transitions.
    failure_count: u64,
    /// Last transition timestamp in nanoseconds.
    last_transition_ns: u64,
}

impl CpuHotplugInfo {
    /// Creates a new CPU hotplug info record.
    pub const fn new(cpu_id: u32) -> Self {
        Self {
            cpu_id,
            state: HotplugState::Offline,
            target_state: HotplugState::Offline,
            transitioning: false,
            online_count: 0,
            offline_count: 0,
            failure_count: 0,
            last_transition_ns: 0,
        }
    }

    /// Returns the current hotplug state.
    pub const fn state(&self) -> HotplugState {
        self.state
    }

    /// Returns whether a transition is in progress.
    pub const fn is_transitioning(&self) -> bool {
        self.transitioning
    }

    /// Returns the CPU identifier.
    pub const fn cpu_id(&self) -> u32 {
        self.cpu_id
    }
}

/// A registered callback for a state transition.
#[derive(Debug, Clone)]
pub struct HotplugCallback {
    /// Callback identifier.
    callback_id: u64,
    /// State at which this callback fires.
    trigger_state: HotplugState,
    /// Priority (lower = earlier execution).
    priority: u32,
    /// Whether this callback is for the online path.
    on_online: bool,
    /// Whether this callback is for the offline path.
    on_offline: bool,
    /// Whether this callback is currently enabled.
    enabled: bool,
}

impl HotplugCallback {
    /// Creates a new hotplug callback registration.
    pub const fn new(callback_id: u64, trigger_state: HotplugState, priority: u32) -> Self {
        Self {
            callback_id,
            trigger_state,
            priority,
            on_online: true,
            on_offline: true,
            enabled: true,
        }
    }

    /// Returns the callback identifier.
    pub const fn callback_id(&self) -> u64 {
        self.callback_id
    }

    /// Returns the trigger state.
    pub const fn trigger_state(&self) -> HotplugState {
        self.trigger_state
    }
}

/// Record of a state transition event.
#[derive(Debug, Clone)]
pub struct TransitionRecord {
    /// CPU that transitioned.
    cpu_id: u32,
    /// State transitioned from.
    from_state: HotplugState,
    /// State transitioned to.
    to_state: HotplugState,
    /// Whether the transition succeeded.
    success: bool,
    /// Timestamp in nanoseconds.
    timestamp_ns: u64,
}

impl TransitionRecord {
    /// Creates a new transition record.
    pub const fn new(
        cpu_id: u32,
        from_state: HotplugState,
        to_state: HotplugState,
        success: bool,
    ) -> Self {
        Self {
            cpu_id,
            from_state,
            to_state,
            success,
            timestamp_ns: 0,
        }
    }
}

/// Statistics for the hotplug state machine.
#[derive(Debug, Clone)]
pub struct HotplugStats {
    /// Number of CPUs currently online.
    pub online_count: u32,
    /// Number of CPUs currently offline.
    pub offline_count: u32,
    /// Total successful transitions.
    pub total_transitions: u64,
    /// Total failed transitions.
    pub total_failures: u64,
    /// Number of registered callbacks.
    pub callback_count: u32,
}

impl Default for HotplugStats {
    fn default() -> Self {
        Self::new()
    }
}

impl HotplugStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            online_count: 0,
            offline_count: 0,
            total_transitions: 0,
            total_failures: 0,
            callback_count: 0,
        }
    }
}

/// Central CPU hotplug state machine.
#[derive(Debug)]
pub struct CpuHotplugStateMachine {
    /// Per-CPU info.
    cpus: [Option<CpuHotplugInfo>; MAX_CPUS],
    /// Registered callbacks.
    callbacks: [Option<HotplugCallback>; MAX_CALLBACKS_PER_STATE],
    /// Transition log ring buffer.
    transition_log: [Option<TransitionRecord>; MAX_TRANSITION_LOG],
    /// Write position in transition log.
    log_pos: usize,
    /// Number of registered CPUs.
    cpu_count: usize,
    /// Number of registered callbacks.
    callback_count: usize,
    /// Next callback identifier.
    next_callback_id: u64,
    /// Total successful transitions.
    total_transitions: u64,
    /// Total failed transitions.
    total_failures: u64,
}

impl Default for CpuHotplugStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuHotplugStateMachine {
    /// Creates a new CPU hotplug state machine.
    pub const fn new() -> Self {
        Self {
            cpus: [const { None }; MAX_CPUS],
            callbacks: [const { None }; MAX_CALLBACKS_PER_STATE],
            transition_log: [const { None }; MAX_TRANSITION_LOG],
            log_pos: 0,
            cpu_count: 0,
            callback_count: 0,
            next_callback_id: 1,
            total_transitions: 0,
            total_failures: 0,
        }
    }

    /// Registers a CPU with the state machine.
    pub fn register_cpu(&mut self, cpu_id: u32) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if self.cpus[idx].is_some() {
            return Err(Error::AlreadyExists);
        }
        self.cpus[idx] = Some(CpuHotplugInfo::new(cpu_id));
        self.cpu_count += 1;
        Ok(())
    }

    /// Transitions a CPU to the next state toward the target.
    pub fn transition(&mut self, cpu_id: u32, target: HotplugState) -> Result<HotplugState> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let cpu = self.cpus[idx].as_mut().ok_or(Error::NotFound)?;
        if cpu.transitioning {
            return Err(Error::Busy);
        }
        let from = cpu.state;
        cpu.transitioning = true;
        cpu.target_state = target;
        cpu.state = target;
        cpu.transitioning = false;
        cpu.last_transition_ns += 1;
        // Track online/offline counts.
        match target {
            HotplugState::OnlineActive | HotplugState::OnlineIdle => {
                cpu.online_count += 1;
            }
            HotplugState::Offline | HotplugState::Removed => {
                cpu.offline_count += 1;
            }
            _ => {}
        }
        let record = TransitionRecord::new(cpu_id, from, target, true);
        self.transition_log[self.log_pos] = Some(record);
        self.log_pos = (self.log_pos + 1) % MAX_TRANSITION_LOG;
        self.total_transitions += 1;
        Ok(target)
    }

    /// Registers a callback for hotplug transitions.
    pub fn register_callback(&mut self, trigger_state: HotplugState, priority: u32) -> Result<u64> {
        if self.callback_count >= MAX_CALLBACKS_PER_STATE {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_callback_id;
        self.next_callback_id += 1;
        let cb = HotplugCallback::new(id, trigger_state, priority);
        if let Some(slot) = self.callbacks.iter_mut().find(|s| s.is_none()) {
            *slot = Some(cb);
            self.callback_count += 1;
            Ok(id)
        } else {
            Err(Error::OutOfMemory)
        }
    }

    /// Unregisters a callback.
    pub fn unregister_callback(&mut self, callback_id: u64) -> Result<()> {
        let slot = self
            .callbacks
            .iter_mut()
            .find(|s| s.as_ref().map_or(false, |cb| cb.callback_id == callback_id))
            .ok_or(Error::NotFound)?;
        *slot = None;
        self.callback_count -= 1;
        Ok(())
    }

    /// Returns the current state of a CPU.
    pub fn cpu_state(&self, cpu_id: u32) -> Result<HotplugState> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.cpus[idx]
            .as_ref()
            .map(|c| c.state)
            .ok_or(Error::NotFound)
    }

    /// Returns aggregate statistics.
    pub fn stats(&self) -> HotplugStats {
        let mut s = HotplugStats::new();
        for cpu in self.cpus.iter().flatten() {
            match cpu.state {
                HotplugState::OnlineActive | HotplugState::OnlineIdle => s.online_count += 1,
                _ => s.offline_count += 1,
            }
        }
        s.total_transitions = self.total_transitions;
        s.total_failures = self.total_failures;
        s.callback_count = self.callback_count as u32;
        s
    }

    /// Returns the number of registered CPUs.
    pub const fn cpu_count(&self) -> usize {
        self.cpu_count
    }
}
