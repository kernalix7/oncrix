// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Performance monitoring events (perf_event_open-style).
//!
//! Provides hardware and software performance counters for profiling
//! and tracing. Supports per-CPU and per-process event monitoring.
//!
//! # Supported Event Types
//!
//! | Type      | Events                                    |
//! |-----------|-------------------------------------------|
//! | Hardware  | CPU cycles, instructions, cache refs/miss |
//! | Software  | Context switches, page faults, task clock |
//! | Tracepoint| Syscall entry/exit, scheduler events      |

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum simultaneous perf events.
const MAX_EVENTS: usize = 64;

/// Maximum perf event groups.
const _MAX_GROUPS: usize = 16;

/// Sample buffer size (ring buffer entries).
const SAMPLE_BUFFER_SIZE: usize = 1024;

// ---------------------------------------------------------------------------
// Event Type
// ---------------------------------------------------------------------------

/// Top-level event type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PerfType {
    /// Hardware performance counter.
    Hardware = 0,
    /// Software performance counter.
    Software = 1,
    /// Tracepoint event.
    Tracepoint = 2,
    /// Hardware cache event.
    HwCache = 3,
    /// Raw hardware event (PMU-specific).
    Raw = 4,
}

impl PerfType {
    /// Convert from raw u32.
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::Hardware),
            1 => Some(Self::Software),
            2 => Some(Self::Tracepoint),
            3 => Some(Self::HwCache),
            4 => Some(Self::Raw),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Hardware Events
// ---------------------------------------------------------------------------

/// Hardware performance counter event IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum HwEvent {
    /// Total CPU cycles.
    CpuCycles = 0,
    /// Retired instructions.
    Instructions = 1,
    /// Cache references.
    CacheReferences = 2,
    /// Cache misses.
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
    RefCpuCycles = 9,
}

impl HwEvent {
    /// Convert from raw u64.
    pub fn from_u64(val: u64) -> Option<Self> {
        match val {
            0 => Some(Self::CpuCycles),
            1 => Some(Self::Instructions),
            2 => Some(Self::CacheReferences),
            3 => Some(Self::CacheMisses),
            4 => Some(Self::BranchInstructions),
            5 => Some(Self::BranchMisses),
            6 => Some(Self::BusCycles),
            7 => Some(Self::StalledCyclesFrontend),
            8 => Some(Self::StalledCyclesBackend),
            9 => Some(Self::RefCpuCycles),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Software Events
// ---------------------------------------------------------------------------

/// Software performance counter event IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SwEvent {
    /// Context switches.
    ContextSwitches = 0,
    /// CPU migrations.
    CpuMigrations = 1,
    /// Page faults (minor + major).
    PageFaults = 2,
    /// Minor page faults (no I/O).
    PageFaultsMin = 3,
    /// Major page faults (required I/O).
    PageFaultsMaj = 4,
    /// Alignment faults.
    AlignmentFaults = 5,
    /// Emulation faults.
    EmulationFaults = 6,
    /// Task clock (nanoseconds of CPU time).
    TaskClock = 7,
    /// CPU clock (wall-clock nanoseconds while on-CPU).
    CpuClock = 8,
}

impl SwEvent {
    /// Convert from raw u64.
    pub fn from_u64(val: u64) -> Option<Self> {
        match val {
            0 => Some(Self::ContextSwitches),
            1 => Some(Self::CpuMigrations),
            2 => Some(Self::PageFaults),
            3 => Some(Self::PageFaultsMin),
            4 => Some(Self::PageFaultsMaj),
            5 => Some(Self::AlignmentFaults),
            6 => Some(Self::EmulationFaults),
            7 => Some(Self::TaskClock),
            8 => Some(Self::CpuClock),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Event Attributes
// ---------------------------------------------------------------------------

/// Configuration for a perf event.
#[derive(Debug, Clone, Copy)]
pub struct PerfEventAttr {
    /// Event type.
    pub perf_type: PerfType,
    /// Event-specific configuration (event ID).
    pub config: u64,
    /// Sample period (0 = counting mode).
    pub sample_period: u64,
    /// Sample type flags.
    pub sample_type: u64,
    /// Whether to exclude kernel space.
    pub exclude_kernel: bool,
    /// Whether to exclude user space.
    pub exclude_user: bool,
    /// Whether the event is disabled initially.
    pub disabled: bool,
    /// Whether to inherit to child processes.
    pub inherit: bool,
    /// PID to monitor (0 = calling process, -1 = all).
    pub pid: i32,
    /// CPU to monitor (-1 = all).
    pub cpu: i32,
    /// Group leader fd (-1 = no group).
    pub group_fd: i32,
}

impl Default for PerfEventAttr {
    fn default() -> Self {
        Self {
            perf_type: PerfType::Hardware,
            config: 0,
            sample_period: 0,
            sample_type: 0,
            exclude_kernel: false,
            exclude_user: false,
            disabled: true,
            inherit: false,
            pid: 0,
            cpu: -1,
            group_fd: -1,
        }
    }
}

// ---------------------------------------------------------------------------
// Sample Type Flags
// ---------------------------------------------------------------------------

/// Sample includes IP (instruction pointer).
pub const PERF_SAMPLE_IP: u64 = 1 << 0;

/// Sample includes TID (thread ID).
pub const PERF_SAMPLE_TID: u64 = 1 << 1;

/// Sample includes timestamp.
pub const PERF_SAMPLE_TIME: u64 = 1 << 2;

/// Sample includes address.
pub const PERF_SAMPLE_ADDR: u64 = 1 << 3;

/// Sample includes counter value.
pub const PERF_SAMPLE_READ: u64 = 1 << 4;

/// Sample includes callchain.
pub const PERF_SAMPLE_CALLCHAIN: u64 = 1 << 5;

/// Sample includes CPU number.
pub const PERF_SAMPLE_CPU: u64 = 1 << 7;

/// Sample includes period.
pub const PERF_SAMPLE_PERIOD: u64 = 1 << 8;

// ---------------------------------------------------------------------------
// Perf Event Instance
// ---------------------------------------------------------------------------

/// State of a single perf event.
#[derive(Debug, Clone, Copy, Default)]
pub struct PerfEvent {
    /// Event attributes.
    pub attr: PerfEventAttr,
    /// Whether the event is currently enabled.
    pub enabled: bool,
    /// Current counter value.
    pub count: u64,
    /// Time the event has been enabled (ns).
    pub time_enabled: u64,
    /// Time the event has been running (ns).
    pub time_running: u64,
    /// Event ID (unique per open).
    pub id: u32,
    /// Group leader ID (self if leader).
    pub group_leader: u32,
    /// Whether this slot is active.
    pub active: bool,
}

// ---------------------------------------------------------------------------
// Sample Record
// ---------------------------------------------------------------------------

/// A single performance sample record.
#[derive(Debug, Clone, Copy, Default)]
pub struct PerfSample {
    /// Instruction pointer (if PERF_SAMPLE_IP).
    pub ip: u64,
    /// Process/thread ID (if PERF_SAMPLE_TID).
    pub pid: u32,
    /// Thread ID (if PERF_SAMPLE_TID).
    pub tid: u32,
    /// Timestamp in nanoseconds (if PERF_SAMPLE_TIME).
    pub time: u64,
    /// Address (if PERF_SAMPLE_ADDR).
    pub addr: u64,
    /// CPU number (if PERF_SAMPLE_CPU).
    pub cpu: u32,
    /// Sample period (if PERF_SAMPLE_PERIOD).
    pub period: u64,
}

/// Ring buffer for performance samples.
pub struct SampleBuffer {
    /// Sample entries.
    entries: [PerfSample; SAMPLE_BUFFER_SIZE],
    /// Write position.
    head: usize,
    /// Read position.
    tail: usize,
    /// Number of stored samples.
    count: usize,
    /// Number of lost samples (overflow).
    lost: u64,
}

impl SampleBuffer {
    /// Create an empty sample buffer.
    pub const fn new() -> Self {
        const EMPTY: PerfSample = PerfSample {
            ip: 0,
            pid: 0,
            tid: 0,
            time: 0,
            addr: 0,
            cpu: 0,
            period: 0,
        };
        Self {
            entries: [EMPTY; SAMPLE_BUFFER_SIZE],
            head: 0,
            tail: 0,
            count: 0,
            lost: 0,
        }
    }

    /// Push a sample into the buffer.
    ///
    /// If the buffer is full, the sample is lost and the lost
    /// counter is incremented.
    pub fn push(&mut self, sample: PerfSample) {
        if self.count >= SAMPLE_BUFFER_SIZE {
            self.lost += 1;
            return;
        }
        self.entries[self.head] = sample;
        self.head = (self.head + 1) % SAMPLE_BUFFER_SIZE;
        self.count += 1;
    }

    /// Pop the oldest sample from the buffer.
    pub fn pop(&mut self) -> Option<PerfSample> {
        if self.count == 0 {
            return None;
        }
        let sample = self.entries[self.tail];
        self.tail = (self.tail + 1) % SAMPLE_BUFFER_SIZE;
        self.count -= 1;
        Some(sample)
    }

    /// Returns the number of stored samples.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the number of lost samples.
    pub fn lost(&self) -> u64 {
        self.lost
    }
}

impl Default for SampleBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Perf Event Registry
// ---------------------------------------------------------------------------

/// Global perf event registry.
pub struct PerfEventRegistry {
    /// Event instances.
    events: [PerfEvent; MAX_EVENTS],
    /// Next event ID.
    next_id: u32,
    /// Number of active events.
    count: usize,
}

impl PerfEventRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const EMPTY: PerfEvent = PerfEvent {
            attr: PerfEventAttr {
                perf_type: PerfType::Hardware,
                config: 0,
                sample_period: 0,
                sample_type: 0,
                exclude_kernel: false,
                exclude_user: false,
                disabled: true,
                inherit: false,
                pid: 0,
                cpu: -1,
                group_fd: -1,
            },
            enabled: false,
            count: 0,
            time_enabled: 0,
            time_running: 0,
            id: 0,
            group_leader: 0,
            active: false,
        };
        Self {
            events: [EMPTY; MAX_EVENTS],
            next_id: 1,
            count: 0,
        }
    }

    /// Open a new perf event.
    ///
    /// Returns the event ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the maximum number of
    /// events has been reached.
    pub fn open(&mut self, attr: PerfEventAttr) -> Result<u32> {
        let idx = self
            .events
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id += 1;

        let group_leader = if attr.group_fd >= 0 {
            attr.group_fd as u32
        } else {
            id
        };

        self.events[idx] = PerfEvent {
            attr,
            enabled: !attr.disabled,
            count: 0,
            time_enabled: 0,
            time_running: 0,
            id,
            group_leader,
            active: true,
        };
        self.count += 1;
        Ok(id)
    }

    /// Close a perf event by ID.
    pub fn close(&mut self, id: u32) -> Result<()> {
        let event = self
            .events
            .iter_mut()
            .find(|e| e.active && e.id == id)
            .ok_or(Error::NotFound)?;
        event.active = false;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Enable an event by ID.
    pub fn enable(&mut self, id: u32) -> Result<()> {
        let event = self
            .events
            .iter_mut()
            .find(|e| e.active && e.id == id)
            .ok_or(Error::NotFound)?;
        event.enabled = true;
        Ok(())
    }

    /// Disable an event by ID.
    pub fn disable(&mut self, id: u32) -> Result<()> {
        let event = self
            .events
            .iter_mut()
            .find(|e| e.active && e.id == id)
            .ok_or(Error::NotFound)?;
        event.enabled = false;
        Ok(())
    }

    /// Read the current counter value for an event.
    pub fn read(&self, id: u32) -> Result<PerfReadResult> {
        let event = self
            .events
            .iter()
            .find(|e| e.active && e.id == id)
            .ok_or(Error::NotFound)?;
        Ok(PerfReadResult {
            value: event.count,
            time_enabled: event.time_enabled,
            time_running: event.time_running,
            id: event.id,
        })
    }

    /// Reset a counter to zero.
    pub fn reset(&mut self, id: u32) -> Result<()> {
        let event = self
            .events
            .iter_mut()
            .find(|e| e.active && e.id == id)
            .ok_or(Error::NotFound)?;
        event.count = 0;
        event.time_enabled = 0;
        event.time_running = 0;
        Ok(())
    }

    /// Increment a software event counter.
    ///
    /// Called by the kernel when a software event occurs (e.g.
    /// context switch, page fault).
    pub fn record_sw_event(&mut self, event_id: u64, delta: u64) {
        for event in &mut self.events {
            if event.active
                && event.enabled
                && event.attr.perf_type == PerfType::Software
                && event.attr.config == event_id
            {
                event.count += delta;
            }
        }
    }

    /// Update time accounting for all enabled events.
    pub fn tick(&mut self, elapsed_ns: u64) {
        for event in &mut self.events {
            if event.active {
                event.time_enabled += elapsed_ns;
                if event.enabled {
                    event.time_running += elapsed_ns;
                }
            }
        }
    }

    /// Returns the number of active events.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no events are active.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for PerfEventRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Read Result
// ---------------------------------------------------------------------------

/// Result of reading a perf event counter.
#[derive(Debug, Clone, Copy, Default)]
pub struct PerfReadResult {
    /// Counter value.
    pub value: u64,
    /// Time enabled in nanoseconds.
    pub time_enabled: u64,
    /// Time running in nanoseconds.
    pub time_running: u64,
    /// Event ID.
    pub id: u32,
}

impl PerfReadResult {
    /// Compute the scaled value accounting for multiplexing.
    ///
    /// When events are multiplexed, `time_running < time_enabled`,
    /// so the true count is estimated as:
    /// `value * time_enabled / time_running`.
    pub fn scaled_value(&self) -> u64 {
        if self.time_running == 0 || self.time_running >= self.time_enabled {
            self.value
        } else {
            self.value * self.time_enabled / self.time_running
        }
    }
}
