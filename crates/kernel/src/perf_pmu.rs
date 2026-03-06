// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Performance Monitoring Unit (PMU) — hardware performance counter interface.
//!
//! Provides an abstraction layer for hardware performance monitoring
//! units, allowing the kernel and user-space to count and sample
//! hardware events such as cache misses, branch mispredictions, and
//! instruction counts.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                      PmuSubsystem                            │
//! │                                                              │
//! │  PmuDevice[0..MAX_PMUS]  (registered PMU devices)            │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  pmu_type: PmuType                                     │  │
//! │  │  nr_counters: u16                                      │  │
//! │  │  capabilities: u32                                     │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  PmuEvent[0..MAX_EVENTS]  (active perf events)               │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  event_type: HwEvent                                   │  │
//! │  │  count: u64                                            │  │
//! │  │  config: u64                                           │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `kernel/events/core.c`, `arch/x86/events/core.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum registered PMU devices.
const MAX_PMUS: usize = 16;

/// Maximum active perf events.
const MAX_EVENTS: usize = 256;

/// PMU capability: supports sampling.
pub const PMU_CAP_SAMPLING: u32 = 1 << 0;
/// PMU capability: supports precise event sampling.
pub const PMU_CAP_PRECISE: u32 = 1 << 1;
/// PMU capability: supports per-task counting.
pub const PMU_CAP_PER_TASK: u32 = 1 << 2;
/// PMU capability: supports branch stack.
pub const PMU_CAP_BRANCH_STACK: u32 = 1 << 3;

// ══════════════════════════════════════════════════════════════
// PmuType
// ══════════════════════════════════════════════════════════════

/// Type of PMU device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PmuType {
    /// CPU core PMU.
    Core = 0,
    /// Uncore (off-core) PMU.
    Uncore = 1,
    /// Software PMU (kernel-emulated events).
    Software = 2,
    /// Tracepoint PMU.
    Tracepoint = 3,
    /// Cache-level PMU.
    Cache = 4,
}

impl PmuType {
    /// Display name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Uncore => "uncore",
            Self::Software => "software",
            Self::Tracepoint => "tracepoint",
            Self::Cache => "cache",
        }
    }
}

// ══════════════════════════════════════════════════════════════
// HwEvent
// ══════════════════════════════════════════════════════════════

/// Hardware performance event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HwEvent {
    /// Total CPU cycles.
    CpuCycles = 0,
    /// Retired instructions.
    Instructions = 1,
    /// Cache references (all levels).
    CacheReferences = 2,
    /// Cache misses (all levels).
    CacheMisses = 3,
    /// Branch instructions.
    BranchInstructions = 4,
    /// Branch mispredictions.
    BranchMisses = 5,
    /// Bus cycles.
    BusCycles = 6,
    /// Stalled cycles (frontend).
    StalledCyclesFrontend = 7,
    /// Stalled cycles (backend).
    StalledCyclesBackend = 8,
    /// Reference CPU cycles (not affected by frequency scaling).
    RefCycles = 9,
}

impl HwEvent {
    /// Display name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::CpuCycles => "cpu-cycles",
            Self::Instructions => "instructions",
            Self::CacheReferences => "cache-references",
            Self::CacheMisses => "cache-misses",
            Self::BranchInstructions => "branch-instructions",
            Self::BranchMisses => "branch-misses",
            Self::BusCycles => "bus-cycles",
            Self::StalledCyclesFrontend => "stalled-cycles-frontend",
            Self::StalledCyclesBackend => "stalled-cycles-backend",
            Self::RefCycles => "ref-cycles",
        }
    }
}

// ══════════════════════════════════════════════════════════════
// EventState
// ══════════════════════════════════════════════════════════════

/// State of a perf event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventState {
    /// Slot is free.
    Free = 0,
    /// Event is configured but not started.
    Inactive = 1,
    /// Event is actively counting.
    Active = 2,
    /// Event encountered an error.
    Error = 3,
}

// ══════════════════════════════════════════════════════════════
// PmuDevice
// ══════════════════════════════════════════════════════════════

/// A registered PMU device.
#[derive(Debug, Clone, Copy)]
pub struct PmuDevice {
    /// PMU type.
    pub pmu_type: PmuType,
    /// Number of hardware counters.
    pub nr_counters: u16,
    /// Capability bitmask.
    pub capabilities: u32,
    /// PMU identifier.
    pub pmu_id: u16,
    /// Whether the PMU is registered.
    pub registered: bool,
    /// Number of active events using this PMU.
    pub active_events: u32,
}

impl PmuDevice {
    const fn empty() -> Self {
        Self {
            pmu_type: PmuType::Core,
            nr_counters: 0,
            capabilities: 0,
            pmu_id: 0,
            registered: false,
            active_events: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// PmuEvent
// ══════════════════════════════════════════════════════════════

/// An active performance monitoring event.
#[derive(Debug, Clone, Copy)]
pub struct PmuEvent {
    /// Hardware event type.
    pub event_type: HwEvent,
    /// PMU ID this event is bound to.
    pub pmu_id: u16,
    /// Current counter value.
    pub count: u64,
    /// Event configuration word.
    pub config: u64,
    /// CPU this event is bound to (-1 = any).
    pub cpu: i16,
    /// PID this event is bound to (0 = system-wide).
    pub pid: u64,
    /// Sampling period (0 = counting mode).
    pub sample_period: u64,
    /// Number of samples taken.
    pub sample_count: u64,
    /// Current state.
    pub state: EventState,
}

impl PmuEvent {
    const fn empty() -> Self {
        Self {
            event_type: HwEvent::CpuCycles,
            pmu_id: 0,
            count: 0,
            config: 0,
            cpu: -1,
            pid: 0,
            sample_period: 0,
            sample_count: 0,
            state: EventState::Free,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// PmuStats
// ══════════════════════════════════════════════════════════════

/// Statistics for the PMU subsystem.
#[derive(Debug, Clone, Copy)]
pub struct PmuStats {
    /// Total events created.
    pub total_created: u64,
    /// Total events started.
    pub total_started: u64,
    /// Total events stopped.
    pub total_stopped: u64,
    /// Total counter reads.
    pub total_reads: u64,
    /// Total scheduling conflicts (counter exhaustion).
    pub total_conflicts: u64,
}

impl PmuStats {
    const fn new() -> Self {
        Self {
            total_created: 0,
            total_started: 0,
            total_stopped: 0,
            total_reads: 0,
            total_conflicts: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// PmuSubsystem
// ══════════════════════════════════════════════════════════════

/// Top-level PMU subsystem.
pub struct PmuSubsystem {
    /// Registered PMU devices.
    pmus: [PmuDevice; MAX_PMUS],
    /// Active events.
    events: [PmuEvent; MAX_EVENTS],
    /// Statistics.
    stats: PmuStats,
    /// Next PMU ID.
    next_pmu_id: u16,
    /// Whether the subsystem is initialised.
    initialised: bool,
}

impl Default for PmuSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl PmuSubsystem {
    /// Create a new PMU subsystem.
    pub const fn new() -> Self {
        Self {
            pmus: [const { PmuDevice::empty() }; MAX_PMUS],
            events: [const { PmuEvent::empty() }; MAX_EVENTS],
            stats: PmuStats::new(),
            next_pmu_id: 1,
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

    // ── PMU registration ─────────────────────────────────────

    /// Register a PMU device.
    pub fn register_pmu(
        &mut self,
        pmu_type: PmuType,
        nr_counters: u16,
        capabilities: u32,
    ) -> Result<u16> {
        let slot = self
            .pmus
            .iter()
            .position(|p| !p.registered)
            .ok_or(Error::OutOfMemory)?;

        let pmu_id = self.next_pmu_id;
        self.next_pmu_id += 1;

        self.pmus[slot] = PmuDevice {
            pmu_type,
            nr_counters,
            capabilities,
            pmu_id,
            registered: true,
            active_events: 0,
        };
        Ok(pmu_id)
    }

    // ── Event management ─────────────────────────────────────

    /// Create a new perf event.
    pub fn create_event(
        &mut self,
        event_type: HwEvent,
        pmu_id: u16,
        config: u64,
        cpu: i16,
        pid: u64,
    ) -> Result<usize> {
        // Verify PMU exists.
        if !self.pmus.iter().any(|p| p.registered && p.pmu_id == pmu_id) {
            return Err(Error::NotFound);
        }

        let slot = self
            .events
            .iter()
            .position(|e| matches!(e.state, EventState::Free))
            .ok_or(Error::OutOfMemory)?;

        self.events[slot] = PmuEvent {
            event_type,
            pmu_id,
            count: 0,
            config,
            cpu,
            pid,
            sample_period: 0,
            sample_count: 0,
            state: EventState::Inactive,
        };
        self.stats.total_created += 1;
        Ok(slot)
    }

    /// Start an event.
    pub fn start_event(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_EVENTS {
            return Err(Error::InvalidArgument);
        }
        if !matches!(self.events[slot].state, EventState::Inactive) {
            return Err(Error::InvalidArgument);
        }
        self.events[slot].state = EventState::Active;
        self.stats.total_started += 1;
        Ok(())
    }

    /// Stop an event.
    pub fn stop_event(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_EVENTS {
            return Err(Error::InvalidArgument);
        }
        if !matches!(self.events[slot].state, EventState::Active) {
            return Err(Error::InvalidArgument);
        }
        self.events[slot].state = EventState::Inactive;
        self.stats.total_stopped += 1;
        Ok(())
    }

    /// Read an event's counter.
    pub fn read_event(&mut self, slot: usize) -> Result<u64> {
        if slot >= MAX_EVENTS {
            return Err(Error::InvalidArgument);
        }
        self.stats.total_reads += 1;
        Ok(self.events[slot].count)
    }

    /// Free an event.
    pub fn free_event(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_EVENTS {
            return Err(Error::InvalidArgument);
        }
        self.events[slot] = PmuEvent::empty();
        Ok(())
    }

    // ── Query ────────────────────────────────────────────────

    /// Return statistics.
    pub fn stats(&self) -> PmuStats {
        self.stats
    }

    /// Return the number of registered PMUs.
    pub fn pmu_count(&self) -> usize {
        self.pmus.iter().filter(|p| p.registered).count()
    }

    /// Return the number of active events.
    pub fn active_events(&self) -> usize {
        self.events
            .iter()
            .filter(|e| matches!(e.state, EventState::Active))
            .count()
    }
}
