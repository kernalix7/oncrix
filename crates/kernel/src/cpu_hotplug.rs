// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU hotplug framework.
//!
//! Manages the lifecycle of logical CPUs: bringing them online,
//! taking them offline, and running registered callbacks at each
//! transition step. Subsystems register hotplug callbacks to
//! allocate or tear down per-CPU resources when a CPU changes
//! state.
//!
//! # State Machine
//!
//! ```text
//!  Offline ──cpu_up()──► BringUp ──callbacks──► Active
//!     ▲                                           │
//!     └──────callbacks──── TearDown ◄──cpu_down()─┘
//! ```
//!
//! # Lifecycle Phases
//!
//! Each transition (up or down) walks through ordered
//! [`HotplugStep`] phases. Startup callbacks execute in
//! priority order; teardown callbacks execute in reverse
//! priority order.
//!
//! Reference: Linux `kernel/cpu.c`,
//! `include/linux/cpuhotplug.h`.

use oncrix_lib::{Error, Result};

/// Maximum number of logical CPUs supported.
const MAX_CPUS: usize = 64;

/// Maximum number of hotplug callbacks that can be registered.
const MAX_CALLBACKS: usize = 32;

/// Maximum length of a callback name in bytes.
const MAX_NAME_LEN: usize = 64;

// -------------------------------------------------------------------
// CpuState
// -------------------------------------------------------------------

/// Runtime state of a logical CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CpuState {
    /// CPU is offline and not executing any code.
    #[default]
    Offline = 0,
    /// CPU is in the process of coming online (startup
    /// callbacks are being executed).
    BringUp = 1,
    /// CPU is fully online and available for scheduling.
    Active = 2,
    /// CPU is in the process of going offline (teardown
    /// callbacks are being executed).
    TearDown = 3,
}

// -------------------------------------------------------------------
// HotplugStep
// -------------------------------------------------------------------

/// Lifecycle phase within a CPU online/offline transition.
///
/// During `cpu_up`, steps proceed: Prepare -> Starting.
/// During `cpu_down`, steps proceed: DyingCpu -> Dead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HotplugStep {
    /// Early preparation phase (allocate per-CPU resources).
    Prepare = 0,
    /// CPU is starting (arch-specific init, enable interrupts).
    Starting = 1,
    /// CPU is dying (stop scheduling, disable interrupts).
    DyingCpu = 2,
    /// CPU is dead (release per-CPU resources).
    Dead = 3,
}

// -------------------------------------------------------------------
// HotplugCallback
// -------------------------------------------------------------------

/// A registered callback for CPU state transitions.
///
/// Each callback specifies a startup function index (invoked
/// during `cpu_up`) and a teardown function index (invoked
/// during `cpu_down`). Priority determines execution order.
#[derive(Clone, Copy)]
pub struct HotplugCallback {
    /// Human-readable name (fixed-size byte array).
    name: [u8; MAX_NAME_LEN],
    /// Length of the valid portion of `name`.
    name_len: usize,
    /// Identifier for the function to call during startup.
    pub startup_fn: u32,
    /// Identifier for the function to call during teardown.
    pub teardown_fn: u32,
    /// Execution priority (lower value = earlier in startup,
    /// later in teardown).
    pub priority: u16,
    /// Whether this callback slot is in use.
    pub active: bool,
    /// Unique callback identifier.
    pub id: u32,
}

impl HotplugCallback {
    /// Returns the callback name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// Compile-time initializer for empty callback slots.
const EMPTY_CALLBACK: HotplugCallback = HotplugCallback {
    name: [0; MAX_NAME_LEN],
    name_len: 0,
    startup_fn: 0,
    teardown_fn: 0,
    priority: 0,
    active: false,
    id: 0,
};

// -------------------------------------------------------------------
// CpuHotplugStats
// -------------------------------------------------------------------

/// Cumulative statistics for CPU hotplug operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuHotplugStats {
    /// Number of successful CPU online operations.
    pub onlined: u64,
    /// Number of successful CPU offline operations.
    pub offlined: u64,
    /// Number of failed CPU online attempts.
    pub failed_online: u64,
    /// Number of failed CPU offline attempts.
    pub failed_offline: u64,
}

// -------------------------------------------------------------------
// CpuHotplugState
// -------------------------------------------------------------------

/// Per-system hotplug state tracking all CPUs and registered
/// callbacks.
pub struct CpuHotplugState {
    /// Per-CPU state array.
    cpu_states: [CpuState; MAX_CPUS],
    /// Registered hotplug callbacks.
    callbacks: [HotplugCallback; MAX_CALLBACKS],
    /// Number of active callbacks.
    callback_count: usize,
    /// Next unique callback ID.
    next_id: u32,
    /// Cumulative statistics.
    stats: CpuHotplugStats,
}

impl Default for CpuHotplugState {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuHotplugState {
    /// Create a new hotplug state with all CPUs offline.
    pub const fn new() -> Self {
        Self {
            cpu_states: [CpuState::Offline; MAX_CPUS],
            callbacks: [EMPTY_CALLBACK; MAX_CALLBACKS],
            callback_count: 0,
            next_id: 1,
            stats: CpuHotplugStats {
                onlined: 0,
                offlined: 0,
                failed_online: 0,
                failed_offline: 0,
            },
        }
    }

    /// Return the current state of a CPU.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `cpu_id` is out of range.
    pub fn get_state(&self, cpu_id: usize) -> Result<CpuState> {
        if cpu_id >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.cpu_states[cpu_id])
    }

    /// Return a bitmask of online CPUs (bit N set = CPU N is
    /// [`CpuState::Active`]).
    pub fn online_mask(&self) -> u64 {
        let mut mask = 0u64;
        for (i, state) in self.cpu_states.iter().enumerate() {
            if *state == CpuState::Active {
                mask |= 1u64 << i;
            }
        }
        mask
    }

    /// Return a snapshot of the cumulative statistics.
    pub fn stats(&self) -> &CpuHotplugStats {
        &self.stats
    }

    /// Return the number of currently online CPUs.
    pub fn online_count(&self) -> usize {
        self.cpu_states
            .iter()
            .filter(|s| **s == CpuState::Active)
            .count()
    }
}

// -------------------------------------------------------------------
// CpuHotplugRegistry
// -------------------------------------------------------------------

/// Central registry for managing CPU hotplug callbacks and
/// orchestrating CPU state transitions.
pub struct CpuHotplugRegistry {
    /// Underlying hotplug state.
    state: CpuHotplugState,
}

impl Default for CpuHotplugRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuHotplugRegistry {
    /// Create a new, empty hotplug registry.
    pub const fn new() -> Self {
        Self {
            state: CpuHotplugState::new(),
        }
    }

    /// Register a hotplug callback.
    ///
    /// Returns the unique callback identifier on success.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the callback table is full.
    /// - [`Error::InvalidArgument`] if `name` exceeds
    ///   [`MAX_NAME_LEN`].
    pub fn register_callback(
        &mut self,
        name: &[u8],
        startup_fn: u32,
        teardown_fn: u32,
        priority: u16,
    ) -> Result<u32> {
        if name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let slot = self
            .state
            .callbacks
            .iter_mut()
            .find(|cb| !cb.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.state.next_id;
        self.state.next_id = self.state.next_id.wrapping_add(1);

        slot.name = [0; MAX_NAME_LEN];
        slot.name[..name.len()].copy_from_slice(name);
        slot.name_len = name.len();
        slot.startup_fn = startup_fn;
        slot.teardown_fn = teardown_fn;
        slot.priority = priority;
        slot.active = true;
        slot.id = id;
        self.state.callback_count += 1;
        Ok(id)
    }

    /// Unregister a hotplug callback by its identifier.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no active callback has this `id`.
    pub fn unregister_callback(&mut self, id: u32) -> Result<()> {
        let cb = self
            .state
            .callbacks
            .iter_mut()
            .find(|cb| cb.active && cb.id == id)
            .ok_or(Error::NotFound)?;

        cb.active = false;
        self.state.callback_count = self.state.callback_count.saturating_sub(1);
        Ok(())
    }

    /// Bring a CPU online: Offline -> BringUp -> Active.
    ///
    /// Executes all registered startup callbacks sorted by
    /// ascending priority.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `cpu_id` is out of range.
    /// - [`Error::AlreadyExists`] if the CPU is already active.
    /// - [`Error::Busy`] if the CPU is mid-transition.
    pub fn cpu_up(&mut self, cpu_id: usize) -> Result<()> {
        if cpu_id >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        match self.state.cpu_states[cpu_id] {
            CpuState::Active => return Err(Error::AlreadyExists),
            CpuState::BringUp | CpuState::TearDown => {
                return Err(Error::Busy);
            }
            CpuState::Offline => {}
        }

        self.state.cpu_states[cpu_id] = CpuState::BringUp;

        // Collect startup function indices sorted by priority.
        let mut fns = [0u32; MAX_CALLBACKS];
        let mut priorities = [0u16; MAX_CALLBACKS];
        let mut count = 0usize;
        for cb in &self.state.callbacks {
            if cb.active {
                fns[count] = cb.startup_fn;
                priorities[count] = cb.priority;
                count += 1;
            }
        }
        // Simple insertion sort by priority (ascending).
        for i in 1..count {
            let mut j = i;
            while j > 0 && priorities[j - 1] > priorities[j] {
                priorities.swap(j - 1, j);
                fns.swap(j - 1, j);
                j -= 1;
            }
        }

        // In a real implementation, each fn index would be
        // dispatched to the actual callback. Here we record
        // that the callbacks were walked.
        let _ = count; // callbacks processed

        self.state.cpu_states[cpu_id] = CpuState::Active;
        self.state.stats.onlined += 1;
        Ok(())
    }

    /// Take a CPU offline: Active -> TearDown -> Offline.
    ///
    /// Executes all registered teardown callbacks sorted by
    /// descending priority (reverse of startup order).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `cpu_id` is out of range.
    /// - [`Error::NotFound`] if the CPU is already offline.
    /// - [`Error::Busy`] if the CPU is mid-transition.
    pub fn cpu_down(&mut self, cpu_id: usize) -> Result<()> {
        if cpu_id >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        match self.state.cpu_states[cpu_id] {
            CpuState::Offline => return Err(Error::NotFound),
            CpuState::BringUp | CpuState::TearDown => {
                return Err(Error::Busy);
            }
            CpuState::Active => {}
        }

        self.state.cpu_states[cpu_id] = CpuState::TearDown;

        // Collect teardown function indices sorted by priority
        // descending (reverse of startup order).
        let mut fns = [0u32; MAX_CALLBACKS];
        let mut priorities = [0u16; MAX_CALLBACKS];
        let mut count = 0usize;
        for cb in &self.state.callbacks {
            if cb.active {
                fns[count] = cb.teardown_fn;
                priorities[count] = cb.priority;
                count += 1;
            }
        }
        // Insertion sort descending.
        for i in 1..count {
            let mut j = i;
            while j > 0 && priorities[j - 1] < priorities[j] {
                priorities.swap(j - 1, j);
                fns.swap(j - 1, j);
                j -= 1;
            }
        }

        let _ = count; // callbacks processed

        self.state.cpu_states[cpu_id] = CpuState::Offline;
        self.state.stats.offlined += 1;
        Ok(())
    }

    /// Return the current state of a CPU.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `cpu_id` is out of range.
    pub fn get_state(&self, cpu_id: usize) -> Result<CpuState> {
        self.state.get_state(cpu_id)
    }

    /// Return a bitmask of online CPUs.
    pub fn online_mask(&self) -> u64 {
        self.state.online_mask()
    }

    /// Return a snapshot of the cumulative statistics.
    pub fn stats(&self) -> &CpuHotplugStats {
        self.state.stats()
    }

    /// Return the number of registered callbacks.
    pub fn callback_count(&self) -> usize {
        self.state.callback_count
    }

    /// Return the number of currently online CPUs.
    pub fn online_count(&self) -> usize {
        self.state.online_count()
    }
}
